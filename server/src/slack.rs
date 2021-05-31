use sqlx::PgPool;

use crate::{crypto, models, se, CONFIG};
use chrono::TimeZone;
use std::collections::HashMap;

#[derive(Debug)]
pub enum SlackError {
    Serialize(String),
    Network(String),
    Parse(String),
    Api(String),
}
impl std::fmt::Display for SlackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlackError::Serialize(s) => write!(f, "slack serialize error: {}", s),
            SlackError::Network(s) => write!(f, "slack network error: {}", s),
            SlackError::Parse(s) => write!(f, "slack parse error: {}", s),
            SlackError::Api(s) => write!(f, "slack api error: {}", s),
        }
    }
}
impl std::error::Error for SlackError {}
pub type Result<T> = std::result::Result<T, SlackError>;

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

/// https://api.slack.com/authentication/oauth-v2
/// https://api.slack.com/methods/oauth.v2.access"
pub async fn exchange_access_token(code: &str) -> Result<SlackAccess> {
    let mut resp = surf::post("https://slack.com/api/oauth.v2.access")
        .body(
            surf::Body::from_form(&SlackAccessParams::from_code(code)).map_err(|e| {
                SlackError::Serialize(format!("exchange access form serialize error {:?}", e))
            })?,
        )
        .send()
        .await
        .map_err(|e| SlackError::Network(format!("account request error {:?}", e)))?;
    let access: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| SlackError::Parse(format!("json parse error {:?}", e)))?;
    if access["error"] != serde_json::json!(null) {
        slog::error!(
            crate::LOG,
            "error exchanging slack access token {:?}",
            access
        );
        Err(SlackError::Api(
            access["error"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    } else {
        let access: SlackAccess = serde_json::from_value(access)
            .map_err(|e| SlackError::Parse(format!("json parse from value error {:?}", e)))?;
        Ok(access)
    }
}

pub async fn respond(response_url: &str, message: &str) -> Result<()> {
    let mut resp = surf::post(response_url)
        .header("Content-type", "application/json; charset=utf-8")
        .body(
            surf::Body::from_json(&serde_json::json!({
                "response_type": "ephemeral",
                "text": message,
            }))
            .map_err(|e| SlackError::Serialize(format!("response json serialize error {:?}", e)))?,
        )
        .send()
        .await
        .map_err(|e| SlackError::Network(format!("slack response failed: {}", e)))?;
    let resp: serde_json::Value = resp
        .body_form()
        .await
        .map_err(|e| SlackError::Parse(format!("slack response form parse error {}", e)))?;
    if resp["error"] != serde_json::json!(null) {
        slog::error!(crate::LOG, "error responding to slack url {:?}", resp);
        Err(SlackError::Api(
            resp["error"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    } else {
        Ok(())
    }
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

/// https://api.slack.com/methods/users.info
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

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackMessage {
    pub text: String,
    pub user: String,
    pub team: String,
    pub bot_id: String,
    pub r#type: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackScheduledMessage {
    pub ok: bool,
    pub channel: String,
    pub scheduled_message_id: String,
    pub post_at: u64,
    pub message: SlackMessage,
}

/// https://api.slack.com/messaging/scheduling#scheduling
/// https://api.slack.com/methods/chat.scheduleMessage
pub async fn schedule_message(
    api_token: &str,
    channel: &str,
    text: &str,
    post_at: chrono::DateTime<chrono::Utc>,
) -> Result<SlackScheduledMessage> {
    let mut resp = surf::post("https://slack.com/api/chat.scheduleMessage")
        .header("Content-type", "application/json; charset=utf-8")
        .header("Authorization", format!("Bearer {}", api_token))
        .body(
            surf::Body::from_json(&serde_json::json!({
                "channel": channel,
                "text": text,
                "post_at": post_at.timestamp(),
            }))
            .map_err(|e| SlackError::Serialize(format!("schedule json serialize error {:?}", e)))?,
        )
        .send()
        .await
        .map_err(|e| SlackError::Network(format!("slack schedule failed: {}", e)))?;
    let resp: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| SlackError::Parse(format!("slack schedule parse error {}", e)))?;

    if resp["error"] != serde_json::json!(null) {
        slog::error!(crate::LOG, "error scheduling slack message {:?}", resp);
        Err(SlackError::Api(
            resp["error"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    } else {
        let scheduled: SlackScheduledMessage =
            serde_json::from_value(resp.clone()).map_err(|e| {
                SlackError::Parse(format!(
                    "json parse from value error {:?}\n{}",
                    e,
                    serde_json::to_string_pretty(&resp)
                        .expect("error serializing thing I just serialized")
                ))
            })?;
        Ok(scheduled)
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackListScheduledResponseMetadata {
    next_cursor: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackListScheduledMessage {
    pub id: String,
    pub channel_id: String,
    pub post_at: u64,
    pub date_created: u64,
    pub text: String,
}
impl SlackListScheduledMessage {
    pub fn post_at_dt(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.from_utc_datetime(&chrono::NaiveDateTime::from_timestamp(
            self.post_at as i64,
            0,
        ))
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct SlackListScheduledMessages {
    pub ok: bool,
    pub scheduled_messages: Vec<SlackListScheduledMessage>,
    pub response_metadata: SlackListScheduledResponseMetadata,
}
impl SlackListScheduledMessages {
    pub fn format_messages(&self) -> String {
        let mut s = String::new();
        for msg in &self.scheduled_messages {
            if !s.is_empty() {
                s.push('\n');
            }
            s.push_str(&format!(
                "`{}` [{}]: {}",
                msg.id,
                msg.post_at_dt().to_string(),
                msg.text
            ));
        }
        if s.is_empty() {
            s.push_str("Nothing scheduled");
        }
        s
    }
}

/// https://api.slack.com/messaging/scheduling#listing
/// https://slack.com/api/chat.scheduledMessages.list
pub async fn list_messages(
    api_token: &str,
    channel: &str,
    after_ts: Option<chrono::DateTime<chrono::Utc>>,
    before_ts: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<SlackListScheduledMessages> {
    let mut map = HashMap::new();
    map.insert("channel", Some(channel.to_string()));
    map.insert("after_ts", after_ts.map(|ts| ts.timestamp().to_string()));
    map.insert("before_ts", before_ts.map(|ts| ts.timestamp().to_string()));
    map.retain(|_, v| v.is_some());
    let mut resp = surf::post("https://slack.com/api/chat.scheduledMessages.list")
        .header("Content-type", "application/json; charset=utf-8")
        .header("Authorization", format!("Bearer {}", api_token))
        .body(surf::Body::from_json(&map).map_err(|e| {
            SlackError::Serialize(format!("error serializing list message request: {:?}", e))
        })?)
        .send()
        .await
        .map_err(|e| SlackError::Network(format!("slack list failed: {:?}", e)))?;

    let resp: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| SlackError::Parse(format!("slack list parse error {:?}", e)))?;

    if resp["error"] != serde_json::json!(null) {
        slog::error!(crate::LOG, "error listing slack messages {:?}", resp);
        Err(SlackError::Api(
            resp["error"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    } else {
        let scheduled: SlackListScheduledMessages =
            serde_json::from_value(resp.clone()).map_err(|e| {
                SlackError::Parse(format!(
                    "json parse from value error {:?}\n{}",
                    e,
                    serde_json::to_string_pretty(&resp)
                        .expect("error serializing thing I just serialized")
                ))
            })?;
        Ok(scheduled)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SlackDeleteScheduledMessage {
    error: Option<String>,
}

/// https://api.slack.com/methods/chat.deleteScheduledMessage
pub async fn delete_message(
    api_token: &str,
    channel: &str,
    scheduled_message_id: &str,
) -> Result<SlackDeleteScheduledMessage> {
    let mut resp = surf::post("https://slack.com/api/chat.deleteScheduledMessage")
        .header("Content-type", "application/json; charset=utf-8")
        .header("Authorization", format!("Bearer {}", api_token))
        .body(
            surf::Body::from_json(&serde_json::json!({
                "channel": channel,
                "scheduled_message_id": scheduled_message_id,
            }))
            .map_err(|e| {
                SlackError::Serialize(format!("error serializing delete message request {:?}", e))
            })?,
        )
        .send()
        .await
        .map_err(|e| SlackError::Api(format!("slack delete message failed: {:?}", e)))?;
    let resp: serde_json::Value = resp
        .body_json()
        .await
        .map_err(|e| SlackError::Parse(format!("slack delete message parse error {:?}", e)))?;

    if resp["error"] != serde_json::json!(null) {
        slog::error!(
            crate::LOG,
            "error deleting scheduled slack message {:?}",
            resp
        );
        Err(SlackError::Api(
            resp["error"]
                .as_str()
                .map(String::from)
                .unwrap_or_else(|| "unknown".to_string()),
        ))
    } else {
        let deleted: SlackDeleteScheduledMessage =
            serde_json::from_value(resp.clone()).map_err(|e| {
                SlackError::Parse(format!(
                    "json parse from value error {:?}\n{}",
                    e,
                    serde_json::to_string_pretty(&resp)
                        .expect("error serializing thing I just serialized")
                ))
            })?;
        Ok(deleted)
    }
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
