use sqlx::PgPool;

use crate::{crypto, models, se, CONFIG};
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

pub async fn new_slack_access_token(code: &str) -> crate::Result<SlackAccess> {
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

pub async fn get_user_name_email(
    user_token: &str,
    user_slack_id: &str,
) -> crate::Result<SlackUserInfo> {
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

// pub fn spotify_expiry_seconds_to_epoch_expiration(expires_in: u64) -> crate::Result<i64> {
//     let now = std::time::SystemTime::now();
//     Ok(now
//         .checked_add(std::time::Duration::from_secs(expires_in - 60))
//         .ok_or_else(|| format!("can't add {:?} to time {:?}", expires_in - 60, now))?
//         .duration_since(std::time::UNIX_EPOCH)
//         .map_err(|e| format!("invalid duration {:?}", e))?
//         .as_secs() as i64)
// }

// pub async fn get_currently_playing(
//     pool: &PgPool,
//     user: &models::User,
// ) -> crate::Result<Option<serde_json::Value>> {
//     let access_token = get_user_access_token(pool, user).await?;
//     let mut resp = surf::get("https://api.spotify.com/v1/me/player/currently-playing")
//         .header("authorization", format!("Bearer {}", access_token))
//         .send()
//         .await
//         .map_err(|e| format!("get currently playing error {:?}", e))?;
//     if resp.status() == tide::StatusCode::NoContent {
//         return Ok(None);
//     }
//     let resp: serde_json::Value = resp
//         .body_json()
//         .await
//         .map_err(|e| format!("get currently playing json error {:?}", e))?;
//     Ok(Some(resp))
// }

pub async fn get_user_access_token(pool: &PgPool, user: &models::User) -> crate::Result<String> {
    let slack_token = sqlx::query_as!(
        models::SlackToken,
        "
        select * from slackat.slack_tokens
        where kind = 'user'
            and slack_id = $1
            and slack_team_id = $2;
        ",
        &user.slack_id,
        &user.slack_team_id,
    )
    .fetch_one(pool)
    .await
    .map_err(|e| se!("db error {}", e))?;
    let access_token = crypto::decrypt(&crypto::Enc {
        value: slack_token.encrypted,
        salt: slack_token.salt,
        nonce: slack_token.nonce,
    })?;

    Ok(access_token)
}

// pub async fn get_history(pool: &PgPool, user: &models::User) -> crate::Result<serde_json::Value> {
//     let access_token = get_user_access_token(pool, user).await?;
//     let mut resp = surf::get("https://api.spotify.com/v1/me/player/recently-played?limit=50")
//         .header("authorization", format!("Bearer {}", access_token))
//         .send()
//         .await
//         .map_err(|e| format!("get history error {:?}", e))?;
//     let resp: serde_json::Value = resp
//         .body_json()
//         .await
//         .map_err(|e| format!("get history json error {:?}", e))?;
//     Ok(resp)
// }
