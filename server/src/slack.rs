use sqlx::PgPool;

use crate::{crypto, models, se, CONFIG};
use chrono::TimeZone;
use std::collections::HashMap;
use std::ops::Index;

#[derive(serde::Deserialize, Debug)]
pub struct SlackAccessTeam {
    pub id: String,
    pub name: String,
}
#[derive(serde::Deserialize, Debug)]
pub struct SlackAuthedUser {
    pub id: String,
    pub scope: String,
    pub access_token: String,
    pub token_type: String,
}
#[derive(serde::Deserialize, Debug)]
pub struct SlackAccess {
    pub ok: bool,
    pub app_id: String,
    pub token_type: String,
    pub bot_user_id: String,
    pub access_token: String,
    pub scope: String,
    pub team: SlackAccessTeam,
    pub authed_user: SlackAuthedUser,
}

#[derive(serde::Serialize)]
struct SlackAccessParams {
    client_id: String,
    client_secret: String,
    code: String,
}

impl SlackAccessParams {
    fn from_code(code: &str) -> Self {
        SlackAccessParams {
            client_id: CONFIG.slack_client_id.clone(),
            client_secret: CONFIG.slack_secret_id.clone(),
            code: code.to_string(),
        }
    }
}

pub async fn exchange_access_token(code: &str) -> crate::Result<SlackAccess> {
    let mut resp = surf::post("https://slack.com/api/oauth.v2.access")
        .body(
            surf::Body::from_form(&SlackAccessParams::from_code(code))
                .map_err(|e| se!("exchange access form error {}", e))?,
        )
        .send()
        .await
        .map_err(|e| format!("account request error {:?}", e))?;
    let access: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| se!("json parse error {}", e))?;
    if access.index("error") != &serde_json::json!(null) {
        slog::error!(
            crate::LOG,
            "error exchanging slack access token {:?}",
            access
        );
        Err(se!("error exchanging slack access token {:?}", access).into())
    } else {
        let access: SlackAccess =
            serde_json::from_value(access).map_err(|e| se!("json parse from value error {}", e))?;
        Ok(access)
    }
}

pub async fn respond(response_url: &str, message: &str) -> crate::Result<serde_json::Value> {
    let mut resp = surf::post(response_url)
        .header("Content-type", "application/json; charset=utf-8")
        .body(surf::Body::from_json(&serde_json::json!({
            "response_type": "ephemeral",
            "text": message,
        }))?)
        .send()
        .await
        .map_err(|e| se!("slack response failed: {}", e))?;
    Ok(resp
        .body_form()
        .await
        .map_err(|e| se!("slack response form parse error {}", e))?)
}

#[derive(serde::Deserialize)]
pub struct SlackUser {
    pub id: String,
    pub name: String,
    pub real_name: String,
}

#[derive(serde::Deserialize)]
pub struct SlackUserInfo {
    pub user: SlackUser,
}

#[derive(serde::Serialize)]
struct SlackUserInfoParams {
    pub user: String,
}

#[allow(dead_code)]
pub async fn user_info(user_token: &str, user_slack_id: &str) -> crate::Result<SlackUserInfo> {
    let mut resp = surf::get("https://slack.com/api/users.info")
        .header("authorization", format!("Bearer {}", user_token))
        .body(
            surf::Body::from_form(&SlackUserInfoParams {
                user: user_slack_id.to_string(),
            })
            .map_err(|e| se!("get user form error {}", e))?,
        )
        .send()
        .await
        .map_err(|e| se!("get user error {}", e))?;
    Ok(resp
        .body_json()
        .await
        .map_err(|e| se!("json error {}", e))?)
}

pub async fn schedule_message(
    api_token: &str,
    channel: &str,
    text: &str,
    post_at: chrono::DateTime<chrono::Utc>,
) -> crate::Result<serde_json::Value> {
    let mut resp = surf::post("https://slack.com/api/chat.scheduleMessage")
        .header("Content-type", "application/json; charset=utf-8")
        .header("Authorization", format!("Bearer {}", api_token))
        .body(surf::Body::from_json(&serde_json::json!({
            "channel": channel,
            "text": text,
            "post_at": post_at.timestamp(),
        }))?)
        .send()
        .await
        .map_err(|e| se!("slack schedule failed: {}", e))?;
    Ok(resp
        .body_json()
        .await
        .map_err(|e| se!("slack schedule parse error {}", e))?)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackScheduledResponseMetadata {
    next_cursor: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackScheduledMessage {
    pub id: String,
    pub channel_id: String,
    pub post_at: u64,
    pub date_created: u64,
    pub text: String,
}
impl SlackScheduledMessage {
    pub fn post_at_dt(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.from_utc_datetime(&chrono::NaiveDateTime::from_timestamp(
            self.post_at as i64,
            0,
        ))
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackScheduledMessages {
    pub ok: bool,
    pub scheduled_messages: Vec<SlackScheduledMessage>,
    pub response_metadata: SlackScheduledResponseMetadata,
}
impl SlackScheduledMessages {
    pub fn format_messages(&self) -> String {
        let mut s = String::from("Scheduled:\n");
        for msg in &self.scheduled_messages {
            s.push_str(&format!(
                "`{}` [{}]: {}",
                msg.id,
                msg.post_at_dt().to_string(),
                msg.text
            ));
        }
        s
    }
}

pub async fn list_messages(
    api_token: &str,
    channel: &str,
    after_ts: Option<chrono::DateTime<chrono::Utc>>,
    before_ts: Option<chrono::DateTime<chrono::Utc>>,
) -> crate::Result<SlackScheduledMessages> {
    let mut map = HashMap::new();
    map.insert("channel", Some(channel.to_string()));
    map.insert("after_ts", after_ts.map(|ts| ts.timestamp().to_string()));
    map.insert("before_ts", before_ts.map(|ts| ts.timestamp().to_string()));
    map.retain(|_, v| v.is_some());
    let mut resp = surf::post("https://slack.com/api/chat.scheduledMessages.list")
        .header("Content-type", "application/json; charset=utf-8")
        .header("Authorization", format!("Bearer {}", api_token))
        .body(surf::Body::from_json(&map)?)
        .send()
        .await
        .map_err(|e| se!("slack list failed: {}", e))?;
    Ok(resp
        .body_json()
        .await
        .map_err(|e| se!("slack list parse error {}", e))?)
}

pub async fn get_user_access_token(
    pool: &PgPool,
    slack_user_id: &str,
    slack_team_id: &str,
) -> crate::Result<Option<String>> {
    let slack_token = sqlx::query_as!(
        models::SlackToken,
        "
        select * from slackat.slack_tokens
        where kind = 'user'
            and slack_id = $1
            and slack_team_id = $2;
        ",
        slack_user_id,
        slack_team_id,
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| se!("db error {}", e))?;

    if let Some(slack_token) = slack_token {
        let access_token = crypto::decrypt(&crypto::Enc {
            value: slack_token.encrypted,
            salt: slack_token.salt,
            nonce: slack_token.nonce,
        })?;
        Ok(Some(access_token))
    } else {
        Ok(None)
    }
}
