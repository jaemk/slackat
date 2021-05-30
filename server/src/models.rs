#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct User {
    pub id: i64,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub slack_id: String,
    pub slack_team_id: String,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct AuthToken {
    pub id: i64,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub expires: chrono::DateTime<chrono::Utc>,
    // a user's (of this application) authentication token
    // that is set as cookie on a user's session. This value
    // stored is the hmac (and hex encoded) signature of the
    // actual token returned to the user.
    pub signature: String,
    pub user_id: i64,
}

#[derive(sqlx::FromRow, Debug, serde::Serialize)]
pub struct SlackToken {
    pub id: i64,
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub nonce: String,
    pub salt: String,
    pub kind: String,
    pub slack_id: String,
    pub slack_team_id: String,
    pub scope: Vec<String>,
    pub encrypted: String,
}
