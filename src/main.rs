use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
use chrono::{Duration, Utc};
use dotenv::dotenv;
use serde_json::Value;
use sqlx::{FromRow, PgPool};
use std::{env, net::SocketAddr, sync::Arc};
use stripe::{Event, EventObject, Webhook};
use teloxide::{prelude::*, types::ChatId};
use tokio::time::{sleep, Duration as TokioDuration};

#[derive(FromRow, Debug)]
struct Subscription {
    user_id: i64,
    expires_at: chrono::NaiveDateTime,
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
    let bot = Bot::new(token);

    // Start bot background loop
    let pool_clone = pool.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = check_and_kick_expired(&bot, &pool_clone, group_id).await {
                eprintln!("⚠️ Error in check loop: {}", e);
            }
            sleep(TokioDuration::from_secs(60)).await;
        }
    });

    // Start Stripe webhook server
    let app = Router::new()
        .route("/stripe-webhook", post(handle_stripe_webhook))
        .with_state(pool.clone());

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("🚀 Stripe webhook running on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn check_and_kick_expired(
    bot: &Bot,
    pool: &PgPool,
    group_id: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let expired: Vec<Subscription> = sqlx::query_as!(
        Subscription,
        "SELECT user_id, expires_at FROM subscriptions WHERE expires_at < NOW()"
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

async fn handle_stripe_webhook(
    State(pool): State<Arc<PgPool>>,
    headers: axum::http::HeaderMap,
    body: String,
) -> StatusCode {
    let stripe_secret = env::var("STRIPE_WEBHOOK_SECRET").expect("STRIPE_WEBHOOK_SECRET not set");

    let sig_header = headers
        .get("Stripe-Signature")
        .and_then(|v| v.to_str().ok());

    if sig_header.is_none() {
        return StatusCode::BAD_REQUEST;
    }

    let event = match Webhook::construct_event(&body, sig_header.unwrap(), &stripe_secret) {
        Ok(e) => e,
        Err(_) => return StatusCode::BAD_REQUEST,
    };

    if event.type_ == "checkout.session.completed" {
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

    StatusCode::OK
}
