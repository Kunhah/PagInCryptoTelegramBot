use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use chrono::{Duration, Utc};
use dotenv::dotenv;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use sqlx::types::chrono::DateTime;
use sqlx::types::chrono::NaiveDateTime;
use sqlx::types::chrono::TimeZone;
use std::{env, net::SocketAddr, sync::Arc};
use stripe::{CheckoutSession, CheckoutSessionMode, CreateCheckoutSession, CreateCheckoutSessionLineItems, Event, EventObject, Webhook, Client, Currency, EventType};
use teloxide::{prelude::*, types::ChatId};
use tokio::time::{sleep, Duration as TokioDuration};
use tokio::net::TcpListener;
use std::collections::HashMap;
use teloxide::prelude::*;
use teloxide::dispatching::Dispatcher;
use teloxide::utils::command::BotCommands;
use sqlx::Type;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Type)]
#[sqlx(type_name = "subscription_status", rename_all = "lowercase")]
pub enum SubscriptionStatus {
    Subscribed,
    Active,
    Canceled,
    Expired,
    None,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let db_url = env::var("DATABASE_URL").expect("Missing DATABASE_URL");
    let token = env::var("TELOXIDE_TOKEN").expect("Missing TELOXIDE_TOKEN");
    let group_id = env::var("GROUP_ID")
        .expect("Missing GROUP_ID")
        .parse::<i64>()
        .unwrap();

    let pool = Arc::new(PgPool::connect(&db_url).await.unwrap());
    let bot = Arc::new(Bot::new(token));

    let bot_clone = bot.clone();

    Dispatcher::builder(
        bot.clone(),
        Update::filter_message()
            .filter_command::<Command>()
            .endpoint(answer),
    )
    .default_handler(|upd| async move {
        log::warn!("Unhandled update: {:?}", upd);
    })
    .enable_ctrlc_handler()
    .build()
    .dispatch()
    .await;

    // Start bot background loop
    let pool_clone = pool.clone();
    let pool_clone2 = pool.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = check_and_kick_expired(&bot_clone, &pool_clone, group_id).await {
                eprintln!("⚠️ Error in check loop: {}", e);
            }
            sleep(TokioDuration::from_secs(24 * 60 * 60)).await;
        }
    });

    tokio::spawn(async move {
        loop {
            if let Err(e) = warn_users_expiring_soon(&bot, &pool).await {
                eprintln!("⚠️ Error in warning check: {}", e);
            }
            sleep(TokioDuration::from_secs(24 * 60 * 60)).await;
        }
    });

    let app = Router::new()
        .route("/stripe-webhook", post(handle_stripe_webhook))
        .with_state(pool_clone2);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("🚀 Stripe webhook running on http://{}", addr);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(BotCommands, Clone)]
#[command(rename_rule = "lowercase", description = "These are the available commands:")]
pub enum Command {
    #[command(description = "Inscrição com assinatura cobrada automnáticamente a cada 30 dias.")]
    Inscrever,
    #[command(description = "Faça sua inscrição de forma manual.")]
    Comprar,
    #[command(description = "Renove sua inscrição de forma manual. Se você está usando a assinatura cobrada automaticamente não utilize essa opção")]
    Renovar,
    #[command(description = "Display this text.")]
    Help,
}

pub async fn answer(bot: Bot, msg: Message, command: Command) -> ResponseResult<()> {
    match command {
        Command::Comprar => {
            let telegram_user_id = msg.from.map(|u| u.id.0 as i64).unwrap_or(0);

            match create_stripe_checkout_session(telegram_user_id, false).await {
                Ok(url) => {
                    bot.send_message(msg.chat.id, format!("💳 Por favor compre o accesso aqui:\n{}", url))
                        .await?;
                }
                Err(e) => {
                    bot.send_message(msg.chat.id, format!("❌ Erro ao criar checkout:\n{}", e))
                        .await?;
                }
            }
        }
        Command::Renovar => {
            let telegram_user_id = msg.from.map(|u| u.id.0 as i64).unwrap_or(0);

            match create_stripe_checkout_session(telegram_user_id, false).await {
                Ok(url) => {
                    bot.send_message(msg.chat.id, format!("💳 Por favor renove sua inscrição aqui\n{}", url))
                        .await?;
                }
                Err(e) => {
                    bot.send_message(msg.chat.id, format!("❌ Erro ao criar checkout:\n{}", e))
                        .await?;
                }
            }
        }
        Command::Help => {
            bot.send_message(msg.chat.id, Command::descriptions().to_string())
                .await?;
        }
        Command::Inscrever => {
            let telegram_user_id = msg.from.map(|u| u.id.0 as i64).unwrap_or(0);
            match create_stripe_checkout_session(telegram_user_id, true).await {
                Ok(url) => {
                    bot.send_message(msg.chat.id, format!("💳 Por favor faça sua inscrição aqui:\n{}", url))
                        .await?;
                }
                Err(e) => {
                    bot.send_message(msg.chat.id, format!("❌ Erro ao criar checkout:\n{}", e))
                        .await?;
                }
            }
        }
    }
    Ok(())
}

async fn check_and_kick_expired(
    bot: &Bot,
    pool: &PgPool,
    group_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let expired = sqlx::query!(
        r#"
        SELECT telegram_user_id
        FROM subscriptions
        WHERE current_period_end < now()
          AND status IN ('active', 'canceled', 'expired')
        "#
    )
    .fetch_all(pool)
    .await?;

    for sub in expired {
        println!("⛔ Removing expired user: {}", sub.telegram_user_id);
        match bot.ban_chat_member(ChatId(group_id), UserId(sub.telegram_user_id as u64)).await {
            Ok(_) => {
                sqlx::query!("DELETE FROM subscriptions WHERE telegram_user_id = $1", sub.telegram_user_id)
                    .execute(pool)
                    .await?;
                println!("✅ User {} removed", sub.telegram_user_id);
            }
            Err(e) => {
                eprintln!("⚠️ Could not remove user {}: {}", sub.telegram_user_id, e);
            }
        }
    }

    Ok(())
}

async fn warn_users_expiring_soon(bot: &Bot, pool: &PgPool) -> Result<(), sqlx::Error> {
    let soon = sqlx::query!(
        r#"
        SELECT telegram_user_id, current_period_end
        FROM subscriptions
        WHERE current_period_end::date = (now() + interval '7 days')::date
          AND status = 'active'
        "#
    )
    .fetch_all(pool)
    .await?;

    for record in soon {
        let id = record.telegram_user_id;
        let days = chrono::Utc::now().naive_utc().date().signed_duration_since(record.current_period_end.date()).num_days().abs();
        let message = match days {
            0 => "🚨 Sua inscrição expirou, por favor renove para acessar".to_string(),
            1 => "⚠️ Sua inscrição expira amanhã!".to_string(),
            2..3 => format!("⚠️ Sua inscrição irá expirar em {} dias! Por favor renove para manter o acesso.", days),
            _ => format!("Sua inscrição irá expirar em {} dias. Por favor renove para manter o acesso.", days),
        };
        if let Err(err) = bot
            .send_message(UserId(id as u64), message)
            .await
        {
            eprintln!("⚠️ Failed to warn {id}: {err}");
        } else {
            println!("📢 Warned user {id} about expiring subscription");
        }
    }

    Ok(())
}

/// Creates a Stripe Checkout Session for a subscription
pub async fn create_stripe_checkout_session(telegram_user_id: i64, subscribe: bool) -> Result<String, stripe::StripeError> {
    let secret_key = env::var("STRIPE_SECRET_KEY")
        .expect("STRIPE_SECRET_KEY must be set");

    let client = Client::new(secret_key);

    let mode = if subscribe {
        stripe::CheckoutSessionMode::Subscription
    } else {
        stripe::CheckoutSessionMode::Payment
    };

    let metadata_s = {
            let mut map = std::collections::HashMap::new();
            map.insert("telegram_user_id".to_string(), telegram_user_id.to_string());
            map.insert("subscribed".to_string(), subscribe.to_string());
            map
        };

    let params = CreateCheckoutSession {
        metadata: Some(metadata_s.clone()),
        payment_method_types: Some(vec![
            stripe::CreateCheckoutSessionPaymentMethodTypes::Card,
            stripe::CreateCheckoutSessionPaymentMethodTypes::Boleto,
            stripe::CreateCheckoutSessionPaymentMethodTypes::Pix,
        ]),
        success_url: Some("https://example.com/success"),
        cancel_url: Some("https://example.com/cancel"),
        mode: Some(mode),
        subscription_data: if subscribe {
            Some(stripe::CreateCheckoutSessionSubscriptionData {
                metadata: Some(metadata_s),
                ..Default::default()
            })
        } else {
            None
        },
        line_items: Some(vec![CreateCheckoutSessionLineItems {
            price_data: Some(stripe::CreateCheckoutSessionLineItemsPriceData {
                currency: Currency::BRL,
                product_data: Some(stripe::CreateCheckoutSessionLineItemsPriceDataProductData {
                    name: "PagInCrypto Insiders".to_string(),
                    ..Default::default()
                }),
                unit_amount: Some(5000), // $50.00 in cents
                ..Default::default()
            }),
            quantity: Some(1),
            ..Default::default()
        }]),
        ..Default::default()
    };

    let session = stripe::CheckoutSession::create(&client, params).await?;
    Ok(session.url.unwrap_or_default())
}

async fn handle_stripe_webhook(
    State(pool): State<Arc<PgPool>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> StatusCode {
    // This must be your *webhook signing secret* from Stripe dashboard
    let webhook_secret =
        match env::var("STRIPE_WEBHOOK_SECRET") {
            Ok(secret) => secret,
            Err(_) => {
                eprintln!("Missing STRIPE_WEBHOOK_SECRET");
                return StatusCode::INTERNAL_SERVER_ERROR;
            }
        };

    let sig_header = match headers.get("Stripe-Signature").and_then(|v| v.to_str().ok()) {
        std::option::Option::Some(sig) => sig,
        std::option::Option::None => {
            eprintln!("Missing Stripe-Signature header");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Verify webhook signature
    let event = match stripe::Webhook::construct_event(&body, sig_header, &webhook_secret) {
        Ok(evt) => evt,
        Err(err) => {
            eprintln!("⚠️ Webhook signature verification failed: {err}");
            return StatusCode::BAD_REQUEST;
        }
    };

    // Match and handle event types
    match event.type_ {
        EventType::CheckoutSessionCompleted => {
            handle_checkout_session_completed(event, pool.clone()).await;
        }
        EventType::InvoicePaid => {
            handle_stripe_invoice_paid(event, pool.clone()).await;
        }
        EventType::CustomerSubscriptionDeleted => {
            handle_subscription_deleted(event, pool.clone()).await;
        }
        _ => {
            println!("Unhandled event type: {}", event.type_);
        }
    }

    StatusCode::OK
}

async fn handle_checkout_session_completed(event: Event, pool: Arc<PgPool>) {
    if let EventObject::CheckoutSession(session) = event.data.object {
        if let Some(metadata) = session.metadata {
            if let Some(user_id_str) = metadata.get("telegram_user_id") {
                if let Some(subscribed) = metadata.get("subscribed") {
                    if let Ok(user_id) = user_id_str.parse::<i64>() {
                        if let Some(sub_id) = &session.subscription {
                            // Check if already subscribed
                            let existing = sqlx::query!(
                                r#"
                                SELECT status as "status: SubscriptionStatus", current_period_end
                                FROM subscriptions
                                WHERE telegram_user_id = $1
                                "#,
                                user_id
                            )
                            .fetch_optional(pool.as_ref())
                            .await
                            .unwrap();

                            let mut status: SubscriptionStatus = SubscriptionStatus::Active;

                            let new_period_end = if let Some(record) = existing {
                                if record.status == SubscriptionStatus::Active {
                                    eprintln!("❌ User {} is already subscribed, skipping update.", user_id);
                                    return;
                                }
                                status = record.status;

                                if record.current_period_end > chrono::Utc::now().naive_utc() {
                                        record.current_period_end + chrono::Duration::days(30)
                                } else {
                                    chrono::Utc::now().naive_utc() + chrono::Duration::days(30)
                                }
                            }
                            else {
                                chrono::Utc::now().naive_utc() + chrono::Duration::days(30)
                            };
                            

                            // Calculate new period_end
                            //let new_period_end = if let Some(record) = existing {
                                //if let Some(end) = record.current_period_end {
                                    // Extend from the greater of (existing, now)
                                    // if record.current_period_end > chrono::Utc::now().naive_utc() {
                                    //     record.current_period_end + chrono::Duration::days(30)
                                    // } else {
                                    //     chrono::Utc::now().naive_utc() + chrono::Duration::days(30)
                                    // }
                                // } else {
                                //     chrono::Utc::now() + chrono::Duration::days(30)
                                // }
                            //} else {
                                //chrono::Utc::now().naive_utc() + chrono::Duration::days(30)
                            //};
                            // subscribed.parse::<bool>().unwrap_or_default()

                            if status == SubscriptionStatus::Active {
                                if let Err(err) = sqlx::query!(
                                    r#"
                                    INSERT INTO subscriptions (telegram_user_id, id, status, current_period_end, updated_at)
                                    VALUES ($1, $2, 'active', $3, NOW())
                                    ON CONFLICT (telegram_user_id)
                                    DO UPDATE
                                    SET id = $2,
                                        status = 'active',
                                        current_period_end = $3,
                                        updated_at = NOW();
                                    "#,
                                    user_id,
                                    sub_id.id().to_string().parse::<i32>().unwrap_or_default(),   // store as text, not i32
                                    new_period_end
                                )
                                .execute(pool.as_ref())
                                .await
                                {
                                    eprintln!("❌ DB update error for user {}: {}", user_id, err);
                                } else {
                                    println!("✅ Linked Stripe subscription {} to Telegram user {}, new period end = {}", sub_id.id(), user_id, new_period_end);
                                }
                            }
                            else if status == SubscriptionStatus::Subscribed {
                                if let Err(err) = sqlx::query!(
                                    r#"
                                    INSERT INTO subscriptions (telegram_user_id, id, status, current_period_end, updated_at)
                                    VALUES ($1, $2, 'active', $3, NOW())
                                    ON CONFLICT (telegram_user_id)
                                    DO UPDATE
                                    SET id = $2,
                                        status = 'subscribed',
                                        current_period_end = $3,
                                        updated_at = NOW();
                                    "#,
                                    user_id,
                                    sub_id.id().to_string().parse::<i32>().unwrap_or_default(),   // store as text, not i32
                                    new_period_end
                                )
                                .execute(pool.as_ref())
                                .await
                                {
                                    eprintln!("❌ DB update error for user {}: {}", user_id, err);
                                } else {
                                    println!("✅ Linked Stripe subscription {} to Telegram user {}, new period end = {}", sub_id.id(), user_id, new_period_end);
                                }
                            }                       
                        }
                    }
                }
            }
        }
    }
}

async fn handle_stripe_invoice_paid(event: Event, pool: Arc<PgPool>) {
    let data = event.data.object;

    if let Ok(invoice) = serde_json::from_value::<stripe::Invoice>(serde_json::to_value(data.clone()).unwrap_or_default()) {
        // Retrieve subscription info from Stripe if present
        if let Some(sub_id) = invoice.subscription.as_ref() {
            let client = stripe::Client::new(&std::env::var("STRIPE_SECRET_KEY").unwrap_or_default());

            let sub = match stripe::Subscription::retrieve(&client, &sub_id.id(), &[]).await {
                Ok(sub) => sub,
                Err(err) => {
                    eprintln!("⚠️ Failed to retrieve subscription {}: {:?}", sub_id.id(), err);
                    return;
                }
            };

            // Telegram user ID is stored in subscription metadata
            if let Some(user_id_str) = sub.metadata.get("telegram_user_id") {
                if let Ok(user_id) = user_id_str.parse::<i64>() {
                    // if let Some(period_end) = invoice.period_end {
                        if let Some(period_end_dt) = chrono::DateTime::from_timestamp(sub.current_period_end as i64, 0) {
                            let _ = sqlx::query!(
                                "UPDATE subscriptions
                                SET current_period_end = $2,
                                    updated_at = NOW()
                                WHERE telegram_user_id = $1",
                                user_id, // ensure it's a BIGINT
                                period_end_dt.naive_utc()
                            )
                            .execute(&*pool)
                            .await;
    
                            println!("✅ Activated subscription for Telegram user {user_id}");
                        }
                    //}
                }
            }
        }
    }
}

async fn handle_subscription_deleted(event: Event, pool: Arc<PgPool>) {
    let data = event.data.object;

    if let Ok(subscription) = serde_json::from_value::<stripe::Subscription>(
        serde_json::to_value(data.clone()).unwrap_or_default()
    ) {
        if let Some(user_id) = subscription.metadata.get("telegram_user_id") {
            if let Some(subscribed) = subscription.metadata.get("subscribed") {
                if subscribed.parse::<bool>().unwrap_or_default() {

                    let telegram_user_id = user_id.parse::<i64>().unwrap_or_default();
        
                    // Detect cancellation reason
                    let reason = subscription
                        .cancellation_details
                        .as_ref()
                        .and_then(|d| d.reason.clone())
                        .unwrap_or_else(|| stripe::CancellationDetailsReason::PaymentFailed);
        
                    // let status: SubscriptionStatus = match reason {
                    //     stripe::CancellationDetailsReason::PaymentFailed => SubscriptionStatus::Expired,
                    //     stripe::CancellationDetailsReason::CancellationRequested => SubscriptionStatus::Canceled,
                    //     _ => SubscriptionStatus::None,
                    // };
                    match reason {
                        stripe::CancellationDetailsReason::PaymentFailed => {
                            let _ = sqlx::query!(
                                r#"
                                UPDATE subscriptions
                                SET status = 'expired'
                                WHERE telegram_user_id = $1
                                "#,
                                telegram_user_id,
                            )
                            .execute(&*pool)
                            .await;
                            },
                        stripe::CancellationDetailsReason::CancellationRequested => {
                            let _ = sqlx::query!(
                                r#"
                                UPDATE subscriptions
                                SET status = 'canceled'
                                WHERE telegram_user_id = $1
                                "#,
                                telegram_user_id,
                            )
                            .execute(&*pool)
                            .await;
                        },
                        _ => {
                            let _ = sqlx::query!(
                                r#"
                                UPDATE subscriptions
                                SET status = 'expired'
                                WHERE telegram_user_id = $1
                                "#,
                                telegram_user_id,
                            )
                            .execute(&*pool)
                            .await;
                        }
                    };
                    
        
                    match reason.as_str() {
                        "payment_failed" => {
                            println!("❌ Subscription for user {telegram_user_id} auto-canceled by Stripe due to failed payment");
                            // Here you can trigger bot action, like warning or immediate removal
                        }
                        "cancellation_requested" => {
                            println!("👋 User {telegram_user_id} manually canceled subscription");
                        }
                        other => {
                            println!("⚠️ Subscription for {telegram_user_id} canceled, reason: {other}");
                        }
                    }
                }
            }
        }
    }
}