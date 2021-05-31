use cached::Cached;
use chrono::{Duration, TimeZone, Utc};
use regex::Regex;
use sqlx::PgPool;

use crate::slack::get_user_access_token;
use crate::{crypto, models, resp, se, slack, Result, CONFIG, LOG};

macro_rules! user_or_redirect {
    ($req:expr) => {{
        let user = get_auth_user(&$req).await;
        if user.is_none() {
            let path = $req.url().path();
            return Ok(
                tide::Redirect::new(format!("{}?redirect={}", CONFIG.login_url(), path)).into(),
            );
        }
        user.unwrap()
    }};
}

#[allow(unused_macros)]
macro_rules! params_or_error {
    ($req:expr, $param_type:ty) => {{
        match $req.query::<$param_type>() {
            Err(e) => {
                slog::error!(LOG, "invalid recent query params {:?}", e);
                return Ok(resp!(status => 400, message => "invalid query parameters"));
            }
            Ok(params) => params,
        }
    }};
}

#[derive(Clone)]
struct Context {
    pool: sqlx::PgPool,
}

pub async fn start(pool: sqlx::PgPool) -> crate::Result<()> {
    let ctx = Context { pool };
    let mut app = tide::with_state(ctx);
    app.at("/").all(index);
    app.at("/status").all(status);
    app.at("/login").get(login);
    app.at("/login/slack").get(auth_callback);
    app.at("/slack/command").post(slack_command);
    app.with(crate::logging::LogMiddleware::new());

    slog::info!(LOG, "running at {}", crate::CONFIG.host());
    app.listen(crate::CONFIG.host()).await?;
    Ok(())
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SlackCommand {
    pub team_id: String,
    pub team_domain: String,
    pub channel_id: String,
    pub user_id: String,
    pub user_name: String,
    pub command: String,
    pub text: String,
    pub api_app_id: String,
    pub is_enterprise_install: bool,
    pub response_url: String,
    pub trigger_id: String,
}

struct ScheduleArgs {
    text: String,
    post_at: chrono::DateTime<chrono::Utc>,
}
enum ParsedCommand {
    Schedule(ScheduleArgs),
    List,
    Cancel(String),
    Help,
    Error(String),
}

fn _is_help(s: &str) -> bool {
    lazy_static::lazy_static! {
        static ref HELP_RE: Regex = Regex::new("^(h|-h|help|--help)$").unwrap();
    }
    HELP_RE.is_match(s)
}

fn _is_list(s: &str) -> bool {
    lazy_static::lazy_static! {
        static ref LIST_RE: Regex = Regex::new("^(l|-l|list|--list)$").unwrap();
    }
    LIST_RE.is_match(s)
}

fn _find_cancel(s: &str) -> Option<&str> {
    lazy_static::lazy_static! {
        static ref CANCEL_RE: Regex = Regex::new(r"(?i)cancel\s?(.*)\s?").unwrap();
    }
    CANCEL_RE
        .captures(s)
        .and_then(|caps| caps.get(1))
        .map(|cap_match| cap_match.as_str())
}

fn _parse_command(cmd: &SlackCommand) -> Result<ParsedCommand> {
    let s = cmd.text.trim();
    if _is_help(s) {
        return Ok(ParsedCommand::Help);
    }
    if _is_list(s) {
        return Ok(ParsedCommand::List);
    }
    if let Some(cancel_message_id) = _find_cancel(s) {
        return Ok(ParsedCommand::Cancel(cancel_message_id.to_string()));
    }

    if let Some((time, message)) = s.split_once("send") {
        let post_at = match time.split_once("in") {
            Some((_, time)) => {
                let dur = humantime::parse_duration(time.trim())
                    .map_err(|e| se!("error parsing duration: {:?}", e))?;
                chrono::Utc::now()
                    .checked_add_signed(
                        chrono::Duration::from_std(dur)
                            .map_err(|e| se!("invalid duration {:?}", e))?,
                    )
                    .ok_or_else(|| se!("error adding duration"))?
            }
            None => {
                let dur_from_epoch = humantime::parse_rfc3339_weak(time.trim())
                    .map_err(|e| se!("error parsing datetime: {}, {}", time, e))?
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)?;
                chrono::Utc.from_utc_datetime(&chrono::NaiveDateTime::from_timestamp(
                    dur_from_epoch.as_secs() as i64,
                    dur_from_epoch.subsec_nanos(),
                ))
            }
        };
        return Ok(ParsedCommand::Schedule(ScheduleArgs {
            text: message.trim().to_string(),
            post_at,
        }));
    }

    Ok(ParsedCommand::Error(format!(
        "Sorry, couldn't understand what you meant: \"{}\"",
        s
    )))
}

async fn _handle_command(ctx: &Context, cmd: &SlackCommand) -> Result<()> {
    let access_token = get_user_access_token(&ctx.pool, &cmd.user_id, &cmd.team_id).await?;
    if access_token.is_none() {
        slack::respond(
            &cmd.response_url,
            &format!(
                "Whoops, looks like you need to login: {}",
                CONFIG.login_url(),
            ),
        )
        .await
        .map_err(|e| se!("error sending slack response to prompt login {:?}", e))?;
        return Ok(());
    }
    let access_token = access_token.unwrap();
    let parsed = _parse_command(cmd)?;

    let response = match parsed {
        ParsedCommand::Help => Some(String::from("Ex. /at in 20 minutes send Time's up!")),
        ParsedCommand::List => {
            let listed = slack::list_messages(&access_token, &cmd.channel_id, None, None).await?;
            Some(listed.format_messages())
        }
        ParsedCommand::Schedule(ScheduleArgs { text, post_at }) => {
            slack::schedule_message(&access_token, &cmd.channel_id, &text, post_at).await?;
            Some(format!(
                "Scheduled \"{}\" to be sent at {}",
                text,
                post_at.to_string()
            ))
        }
        ParsedCommand::Cancel(message_id) => {
            slog::info!(LOG, "got cancel: {}", message_id);
            Some("cancel!".to_string())
        }
        ParsedCommand::Error(err) => {
            slog::error!(
                LOG,
                "error parsing command {} for user {} {}: {:?}",
                cmd.text,
                cmd.user_id,
                cmd.user_name,
                err
            );
            Some(err)
        }
    };
    if let Some(response) = response {
        slack::respond(&cmd.response_url, &response)
            .await
            .map_err(|e| se!("error sending slack response {:?}", e))?;
    }
    Ok(())
}
async fn handle_command(ctx: Context, cmd: SlackCommand) {
    let start = std::time::Instant::now();
    match _handle_command(&ctx, &cmd).await {
        Err(e) => slog::error!(
            LOG,
            "error handling command \"{}\" for user {} {} [{}ms]: {:?}",
            cmd.text,
            cmd.user_id,
            cmd.user_name,
            start.elapsed().as_millis(),
            e
        ),
        Ok(_) => slog::info!(
            LOG,
            "handled command \"{}\" for user {} {} [{}ms]",
            cmd.text,
            cmd.user_id,
            cmd.user_name,
            start.elapsed().as_millis(),
        ),
    }
}

async fn slack_command(mut req: tide::Request<Context>) -> tide::Result {
    let ctx = req.state().clone();
    let body: SlackCommand = req
        .body_form()
        .await
        .map_err(|e| se!("error decoding json request {:?}", e))?;
    async_std::task::spawn(handle_command(ctx, body));
    return Ok(resp!(status => 200));
}

async fn index(req: tide::Request<Context>) -> tide::Result {
    let user = user_or_redirect!(req);
    return Ok(resp!(status => 200, message => format!("hello, {}!", user.id)));
}

#[derive(serde::Serialize)]
struct Status<'a> {
    ok: &'a str,
    version: &'a str,
}

async fn status(_req: tide::Request<Context>) -> tide::Result {
    Ok(resp!(json => Status {
        ok: "ok",
        version: &CONFIG.version
    }))
}

/// The login process uses slack to authenticate the current user
/// which then redirects back to our callback url with a code we
/// can use to generate a reusable access token.
async fn login(req: tide::Request<Context>) -> tide::Result {
    let maybe_redirect: MaybeRedirect = req.query().map_err(|e| se!("query parse error {}", e))?;
    let token = new_one_time_login_token(maybe_redirect.redirect.clone())
        .await
        .map_err(|e| se!("error generating new one time login token {}", e))?;

    let bot_scope = "commands,channels:read,chat:write";
    let user_scope = "channels:read,chat:write";
    let login_url = format!("https://slack.com/oauth/v2/authorize?scope={bot_scope}&user_scope={user_scope}&state={state}&client_id={client_id}&redirect_uri={redirect}",
                redirect = CONFIG.slack_redirect_url(),
                client_id = CONFIG.slack_client_id,
                state = token,
                user_scope = user_scope,
                bot_scope = bot_scope,
        );
    slog::info!(
        LOG,
        "redirecting to slack-auth with state token, post-redirect-redirect {:?}",
        maybe_redirect.redirect;
        "login_url" => &login_url,
    );
    Ok(tide::Redirect::new(login_url).into())
}

/// After we redirect users to slack to login, slack will send
/// them back to this endpoint. The request will have special
/// query parameters `code` and `state`. `code` is a single-use
/// token that can be used to retrieve a new slack API access token
/// for the user and the team-space's bot. `state` is an arbitrary string
/// that we sent when sending the user to slack. `state` is treated as a
/// one-time-token that we use to assert that this login attempt was one
/// that we initiated and only happens once.
async fn auth_callback(req: tide::Request<Context>) -> tide::Result {
    slog::info!(LOG, "got login redirect");
    let ctx = req.state();
    let auth_callback: AuthCallback = req.query().map_err(|e| se!("query parse error: {:?}", e))?;
    if !is_valid_one_time_login_token(&auth_callback).await {
        return Ok(tide::Response::builder(400)
            .body(serde_json::json!({
                "error": format!("invalid one-time login token {}", auth_callback.state)
            }))
            .build());
    }
    let token_bytes =
        base64::decode(&auth_callback.state).map_err(|e| se!("decode error {}", e))?;
    let token_str = String::from_utf8(token_bytes).map_err(|e| se!("token utf8 error {}", e))?;
    let login_token: OneTimeLoginToken =
        serde_json::from_str(&token_str).map_err(|e| se!("deserialize token error {}", e))?;

    let slack_access = slack::exchange_access_token(&auth_callback.code)
        .await
        .map_err(|e| se!("slack access error {}", e))?;

    // TODO: get user-name, email, and user timezone
    // let name_email = slack::get_new_user_name_email(&slack_access)
    //     .await
    //     .map_err(|e| se!("error getting name {}", e))?;

    let new_auth_token = make_new_auth_token().map_err(|e| se!("new auth tokens error {}", e))?;
    let user = upsert_user_and_slack_tokens(&ctx.pool, &slack_access, &new_auth_token)
        .await
        .map_err(|e| se!("user upsert error {}", e))?;
    let is_new = user.created == user.modified;
    slog::info!(LOG, "completing user login: {}", user.id; "user_id" => user.id, "is_new" => is_new);

    let cookie_str = format!(
        "auth_token={token}; Domain={domain}; Secure; HttpOnly; Max-Age={max_age}; SameSite=Lax; Path=/",
        token = &new_auth_token,
        domain = &CONFIG.domain(),
        max_age = 60 * 24 * 30,
    );

    if let Some(redirect) = login_token.redirect {
        // the one time login token that we sent to slack when
        // redirecting to slacks's auth might have had a redirect
        // url that was the url that the user was originally trying
        // to go to when we noticed that they weren't logged in.
        // If the url they were trying to go to wasn't the login url,
        // then redirect them to it, otherwise just return the user info.
        if !redirect.contains("login") {
            slog::info!(LOG, "found login redirect {:?}", redirect);
            let mut resp: tide::Response =
                tide::Redirect::new(format!("{}{}", CONFIG.real_host(), redirect)).into();
            resp.insert_header("set-cookie", cookie_str);
            return Ok(resp);
        }
    }
    Ok(tide::Response::builder(200)
        .header("set-cookie", cookie_str)
        .body(serde_json::json!({
            "ok": "ok",
            "user.id": user.id,
        }))
        .build())
}

#[derive(Debug, serde::Deserialize)]
struct AuthCallback {
    code: String,
    state: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct OneTimeLoginToken {
    token: String,
    redirect: Option<String>,
}

async fn new_one_time_login_token(redirect: Option<String>) -> Result<String> {
    let s = uuid::Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut uuid::Uuid::encode_buffer())
        .to_string();
    let s = serde_json::to_string(&OneTimeLoginToken { token: s, redirect })
        .map_err(|e| se!("token json error {}", e))?;
    let s = base64::encode_config(&s, base64::URL_SAFE);
    // TODO: encrypt this
    let mut lock = crate::ONE_TIME_TOKENS.lock().await;
    lock.cache_set(s.clone(), ());
    Ok(s)
}

async fn is_valid_one_time_login_token(auth: &AuthCallback) -> bool {
    let mut lock = crate::ONE_TIME_TOKENS.lock().await;
    lock.cache_remove(&auth.state).is_some()
}

#[derive(serde::Deserialize)]
struct MaybeRedirect {
    redirect: Option<String>,
}

fn make_new_auth_token() -> Result<String> {
    let s = uuid::Uuid::new_v4()
        .to_simple()
        .encode_lower(&mut uuid::Uuid::encode_buffer())
        .to_string();
    let n = crypto::rand_bytes(16)?;
    let s = format!("{}:{}", hex::encode(n), s);
    let b = crate::crypto::hash(s.as_bytes());
    Ok(hex::encode(&b))
}

async fn upsert_user_and_slack_tokens(
    pool: &PgPool,
    access: &slack::SlackAccess,
    new_auth_token: &str,
) -> Result<models::User> {
    let auth_token = crypto::hmac_sign(new_auth_token);

    let slack_team_id = &access.team.id;
    let bot_scopes = access
        .scope
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let bot_id = &access.bot_user_id;
    let bot_access_token = crypto::encrypt(&access.access_token)?;

    let user_scopes = access
        .authed_user
        .scope
        .split(',')
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    let user_id = &access.authed_user.id;
    let user_access_token = crypto::encrypt(&access.authed_user.access_token)?;

    let mut tr = pool
        .begin()
        .await
        .map_err(|e| format!("error starting user transaction {:?}", e))?;
    let user = sqlx::query_as!(
        models::User,
        "
        insert into 
        slackat.users (
            slack_id, slack_team_id
        ) 
        values ($1, $2)
        on conflict (slack_id, slack_team_id) do update
            set modified = now()
        returning *
        ",
        user_id,
        slack_team_id,
    )
    .fetch_one(&mut tr)
    .await
    .map_err(|e| format!("error upserting user {:?}", e))?;

    let expires = Utc::now()
        .checked_add_signed(Duration::seconds(CONFIG.auth_expiration_seconds as i64))
        .ok_or("error creating expiration timestamp")?;
    sqlx::query!(
        "
        insert into
        slackat.auth_tokens (
            user_id, signature, expires
        )
        values ($1, $2, $3)
        ",
        &user.id,
        &auth_token,
        &expires,
    )
    .execute(&mut tr)
    .await
    .map_err(|e| format!("failed to insert user auth token {:?}", e))?;

    sqlx::query!(
        "
        insert into
        slackat.slack_tokens (
            nonce, salt, encrypted, kind, slack_id, slack_team_id, scope
        ) values (
            $1, $2, $3, $4, $5, $6, $7
        ) on conflict (kind, slack_id, slack_team_id) do update
            set nonce = excluded.nonce, salt = excluded.salt,
                encrypted = excluded.encrypted, scope = excluded.scope,
                modified = now()
        ",
        &bot_access_token.nonce,
        &bot_access_token.salt,
        &bot_access_token.value,
        "bot",
        &bot_id,
        &slack_team_id,
        &bot_scopes,
    )
    .execute(&mut tr)
    .await
    .map_err(|e| format!("failed to insert bot slack token {:?}", e))?;

    sqlx::query!(
        "
        insert into
        slackat.slack_tokens (
            nonce, salt, encrypted, kind, slack_id, slack_team_id, scope
        ) values (
            $1, $2, $3, $4, $5, $6, $7
        ) on conflict (kind, slack_id, slack_team_id) do update
            set nonce = excluded.nonce, salt = excluded.salt,
                encrypted = excluded.encrypted, scope = excluded.scope
        ",
        &user_access_token.nonce,
        &user_access_token.salt,
        &user_access_token.value,
        "user",
        &user_id,
        &slack_team_id,
        &user_scopes,
    )
    .execute(&mut tr)
    .await
    .map_err(|e| format!("failed to insert user slack token {:?}", e))?;

    tr.commit()
        .await
        .map_err(|e| format!("error committing user/slack-token insert {:?}", e))?;

    Ok(user)
}

async fn get_auth_user(req: &tide::Request<Context>) -> Option<models::User> {
    let ctx = req.state();
    match req.cookie("auth_token") {
        None => {
            slog::info!(LOG, "no auth token cookie found");
            None
        }
        Some(cookie) => {
            let token = cookie.value();
            let hash = crypto::hmac_sign(token);
            let u = sqlx::query_as!(
                models::User,
                "
                select u.*
                from slackat.auth_tokens t
                    inner join slackat.users u
                    on u.id = t.user_id
                where signature = $1
                ",
                &hash,
            )
            .fetch_one(&ctx.pool)
            .await
            .ok();

            slog::debug!(LOG, "current user {:?}", u);
            if let Some(ref u) = u {
                sqlx::query!(
                    "delete from slackat.auth_tokens where user_id = $1 and expires <= now()",
                    &u.id
                )
                .execute(&ctx.pool)
                .await
                .map_err(|e| {
                    format!(
                        "error deleting expired auth tokens for user {}, continuing: {:?}",
                        u.id, e
                    )
                })
                .ok();
            }
            u
        }
    }
}
