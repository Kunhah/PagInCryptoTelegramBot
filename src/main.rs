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

// #[derive(FromRow, Debug)]
// struct Subscription {
//     user_id: i64,
//     expires_at: chrono::NaiveDateTime,
// }

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
    let bot = Bot::new(token);

    // Start bot background loop
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = check_and_kick_expired(&bot, &pool_clone, group_id).await {
                eprintln!("⚠️ Error in check loop: {}", e);
            }
            sleep(TokioDuration::from_secs(24 * 60 * 60)).await;
        }
    });

    let pool_clone2 = pool.clone();
    let bot_clone2 = bot.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = warn_users_expiring_soon(&bot_clone2, &pool_clone2).await {
                eprintln!("⚠️ Error in warning check: {}", e);
            }
            // Run once every 24h
            sleep(TokioDuration::from_secs(24 * 60 * 60)).await;
        }
    });

    // Start Stripe webhook server
    let app = Router::new()
        .route("/stripe-webhook", post(handle_stripe_webhook))
        .with_state(pool.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("🚀 Stripe webhook running on http://{}", addr);

    // axum::Server::bind(&addr)
    //     .serve(app.into_make_service())
    //     .await
    //     .unwrap();
    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn check_and_kick_expired(
    bot: &Bot,
    pool: &PgPool,
    group_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    // let expired: Vec<Subscription> = sqlx::query_as!(
    //     Subscription,
    //     "SELECT user_id, expires_at FROM subscriptions WHERE expires_at < NOW()"
    // )
    // .fetch_all(pool)
    // .await?;
    let expired = sqlx::query!(
        r#"
        SELECT telegram_user_id
        FROM subscriptions
        WHERE current_period_end < now()
          AND status = 'active'
        "#
    )
    .fetch_all(pool)
    .await?;

    for sub in expired {
        println!("⛔ Removing expired user: {}", sub.user_id);
        match bot.ban_chat_member(ChatId(group_id), UserId(sub.user_id as u64)).await {
            Ok(_) => {
                sqlx::query!("DELETE FROM subscriptions WHERE user_id = $1", sub.user_id)
                    .execute(pool)
                    .await?;
                println!("✅ User {} removed", sub.user_id);
            }
            Err(e) => {
                eprintln!("⚠️ Could not remove user {}: {}", sub.user_id, e);
            }
        }
    }

    Ok(())
}

async fn warn_users_expiring_soon(bot: &Bot, pool: &PgPool) -> Result<(), sqlx::Error> {
    let soon = sqlx::query!(
        r#"
        SELECT telegram_user_id
        FROM subscriptions
        WHERE current_period_end::date = (now() + interval '7 days')::date
          AND status = 'active'
        "#
    )
    .fetch_all(pool)
    .await?;

    for record in soon {
        if let Some(user_id) = record.telegram_user_id {
            if let Err(err) = bot
                .send_message(UserId(user_id as u64), "⚠️ Your subscription will expire in 7 days. Please renew to keep access.")
                .await
            {
                eprintln!("⚠️ Failed to warn {user_id}: {err}");
            } else {
                println!("📢 Warned user {user_id} about expiring subscription");
            }
        }
    }

    Ok(())
}

/// Creates a Stripe Checkout Session for a subscription
pub async fn create_checkout_session() -> Result<String, stripe::StripeError> {
    let secret_key = env::var("STRIPE_SECRET_KEY")
        .expect("STRIPE_SECRET_KEY must be set");

    let client = Client::new(secret_key);

    let params = CreateCheckoutSession {
        success_url: Some("https://example.com/success"),
        cancel_url: Some("https://example.com/cancel"),
        mode: Some(stripe::CheckoutSessionMode::Payment),
        line_items: Some(vec![CreateCheckoutSessionLineItems {
            price_data: Some(stripe::CreateCheckoutSessionLineItemsPriceData {
                currency: Currency::USD,
                product_data: Some(stripe::CreateCheckoutSessionLineItemsPriceDataProductData {
                    name: "Example Product".to_string(),
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
        Some(sig) => sig,
        None => {
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
            handle_invoice_paid(event, pool.clone()).await;
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
                if let Ok(user_id) = user_id_str.parse::<i64>() {
                    let expiration = Utc::now() + Duration::days(30);
                    if let Err(err) = sqlx::query!(
                        r#"
                        INSERT INTO subscriptions (user_id, expires_at)
                        VALUES ($1, $2)
                        ON CONFLICT (user_id) DO UPDATE
                        SET expires_at = EXCLUDED.expires_at
                        "#,
                        user_id,
                        expiration.naive_utc()
                    )
                    .execute(pool.as_ref())
                    .await
                    {
                        eprintln!("❌ DB update error for user {}: {}", user_id, err);
                    } else {
                        println!("✅ Subscription updated for Telegram user {}", user_id);
                    }
                }
            }
        }
    }
}

// async fn handle_invoice_paid(event: Event, pool: Arc<PgPool>) {
//     let data = event.data.object;
//     //if let Some(data) = event.data.object {
//         if let Ok(invoice) = serde_json::from_value::<stripe::Invoice>(data.clone()) {
//             // Get Telegram user ID from subscription metadata
//             let telegram_user_id = invoice
//                 .subscription
//                 .as_ref()
//                 .and_then(|sub_id| async {
//                     match stripe::Subscription::retrieve(
//                         &stripe::Client::new(&std::env::var("STRIPE_SECRET_KEY").unwrap()),
//                         sub_id,
//                         &[],
//                     ).await {
//                         Ok(sub) => sub.metadata.get("telegram_user_id").cloned(),
//                         Err(_) => None,
//                     }
//                 })
//                 .await;

//             if let Some(user_id) = telegram_user_id {
//                 if let Some(period_end) = invoice.period_end {
//                     let period_end_dt: DateTime<Utc> =
//                         DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp_opt(period_end as i64, 0).unwrap(), Utc);

//                     let _ = sqlx::query!(
//                         r#"
//                         INSERT INTO subscriptions (telegram_user_id, active, current_period_end)
//                         VALUES ($1, $2, $3)
//                         ON CONFLICT (telegram_user_id)
//                         DO UPDATE SET active = $2, current_period_end = $3
//                         "#,
//                         user_id,
//                         true,
//                         period_end_dt.naive_utc()
//                     )
//                     .execute(&*pool)
//                     .await;
//                     println!("✅ Activated subscription for Telegram user {user_id}");
//                 }
//             }
//         }
//     //}
// }

async fn handle_invoice_paid(event: Event, pool: Arc<PgPool>) {
    let data = event.data.object;

    if let Ok(invoice) = serde_json::from_value::<stripe::Invoice>(serde_json::to_value(data.clone()).unwrap()) {
        // Retrieve subscription info from Stripe if present
        if let Some(sub_id) = invoice.subscription.as_ref() {
            let client = stripe::Client::new(&std::env::var("STRIPE_SECRET_KEY").unwrap());

            let sub = match stripe::Subscription::retrieve(&client, &sub_id.id(), &[]).await {
                Ok(sub) => sub,
                Err(err) => {
                    eprintln!("⚠️ Failed to retrieve subscription {}: {:?}", sub_id.id(), err);
                    return;
                }
            };

            // Telegram user ID is stored in subscription metadata
            if let Some(user_id) = sub.metadata.get("telegram_user_id") {
                if let Some(period_end) = invoice.period_end {
                    if let Some(period_end_dt) = chrono::DateTime::from_timestamp(period_end as i64, 0) {
                        let _ = sqlx::query!(
                            r#"
                            INSERT INTO subscriptions (telegram_user_id, stripe_subscription_id, status, current_period_end)
                            VALUES ($1, $2, $3, $4)
                            ON CONFLICT (telegram_user_id)
                            DO UPDATE
                                SET stripe_subscription_id = $2,
                                    status = $3,
                                    current_period_end = $4,
                                    updated_at = now()
                            "#,
                            user_id.parse::<i64>().unwrap_or_default(), // ensure it's a BIGINT
                            sub.id,
                            "active",
                            period_end_dt.naive_utc()
                        )
                        .execute(&*pool)
                        .await;

                        println!("✅ Activated subscription for Telegram user {user_id}");
                    }
                }
            }
        }
    }
}

async fn handle_subscription_deleted(event: Event, pool: Arc<PgPool>) {
    let data = event.data.object;

    if let Ok(subscription) = serde_json::from_value::<stripe::Subscription>(serde_json::to_value(data.clone()).unwrap()) {
        if let Some(user_id) = subscription.metadata.get("telegram_user_id") {
            let _ = sqlx::query!(
                r#"
                UPDATE subscriptions
                SET status = 'canceled', updated_at = now()
                WHERE telegram_user_id = $1
                "#,
                user_id.parse::<i64>().unwrap_or_default()
            )
            .execute(&*pool)
            .await;

            println!("❌ Deactivated subscription for Telegram user {user_id}");
        }
    }
}