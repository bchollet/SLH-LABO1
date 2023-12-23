use argon2::{self, Config, Variant, verify_encoded, Version};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::Json;
use axum::response::{Html, IntoResponse, Redirect};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use log::{debug, info, trace, warn};
use rand::Rng;
use serde_json::json;
use time::{Duration, OffsetDateTime};
use time::ext::NumericalDuration;
use tower_sessions::Session;
use uuid::Uuid;

use crate::{database, HBS};
use crate::backend::middlewares::AccessUser;
use crate::backend::models::{NewUser, Token, UserLogin};
use crate::database::{token, user};
use crate::database::email::Email;
use crate::database::user::{create, get};
use crate::email::{get_verification_url, send_mail};
use crate::utils::input_validation::{is_login_form_valid, is_register_form_valid};
use crate::utils::jwt::{Role, set_jwt};

pub async fn register(Json(user): Json<NewUser>) -> axum::response::Result<StatusCode> {
    info!("Register new user");
    match is_register_form_valid(&user.email, &user.password, &user.password2) {
        Err(err) => { return Err((StatusCode::INTERNAL_SERVER_ERROR, err).into())}
        Ok(_) => {}
    }

    let hashed_password = hash_password(user.password.as_ref()).to_string();
    if !create(&user.email, hashed_password).unwrap_or(true) {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Account could not be created").into());
    }

    const DAY_IN_SEC: u64 = 24 * 60 * 60;
    let validation_token = rand_base64();
    if token::add(&user.email, &validation_token, core::time::Duration::new(DAY_IN_SEC, 0)).is_err() {
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into());
    }

    let verification_url = get_verification_url(&validation_token);
    let body = format!("Here's the link to validate your email address: {}", verification_url);
    match send_mail(&user.email, "Email confirmation", &body) {
        Ok(_) => Ok(StatusCode::CREATED),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into()),
    }
}

pub async fn verify(Path(token): Path<String>) -> Redirect {
    info!("Verify account");

    let verification =
        match token::consume(token) {
            Ok(email) => {
                match user::verify(&email) {
                    Ok(res) => { res }
                    Err(err) => { warn!("Could not verify email : {err}"); false }
                }
            }
            Err(err) => { warn!("Could not consume token : {err}"); false }
        };

    match verification {
        true => Redirect::to("/?verify=ok"),
        _ => Redirect::to("/?verify=failed"),
    }
}

pub async fn login(Json(user_login): Json<UserLogin>) -> axum::response::Result<Json<Token>> {
    info!("Login user");
    // TODO : Login user
    // TODO : Generate refresh JWT
    match is_login_form_valid(&user_login.email, &user_login.password) {
        Ok(_) => {
            if check_password(&user_login) {
                let jwt = set_jwt(Role::Refresh, &user_login.email);
                return Ok(Json::from(Token { token: jwt }))
            }
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Incorrect email or password").into())
        }
        Err(err) => {
            Err((StatusCode::INTERNAL_SERVER_ERROR, err).into())
        }
    }
}
fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let salt: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();

    // Convert the salt bytes to a hexadecimal string
    let hex_string: String = salt.iter().map(|byte| format!("{:02x}", byte)).collect();

    hex_string
}

fn hash_password(password: &[u8]) -> String {
    let salt = generate_salt();
    let config = Config {
        variant: Variant::Argon2id,
        version: Version::Version13,
        mem_cost: 4096,
        time_cost: 10,
        lanes: 4,
        secret: &[],
        ad: &[],
        hash_length: 32
    };
    argon2::hash_encoded(password, salt.as_ref(), &config).unwrap()
}

fn check_password(user_login: &UserLogin) -> bool {
    const DEFAULT_PASS: &str = "dedce41f-a89c-4f98-8107-ea26bc83752a";
    match get(&user_login.email) {
        None => {
            verify_encoded(DEFAULT_PASS, DEFAULT_PASS.as_ref());
            false
        }
        Some(user) => {
            verify_encoded(&user.hash, user_login.password.as_ref()).unwrap() && user.verified
        }
    }
}

pub fn rand_base64() -> String {
    const TOKEN_CHAR_COUNT: usize = 32;
    let token = rand::thread_rng()
        .sample_iter::<char, _>(rand::distributions::Standard)
        .take(TOKEN_CHAR_COUNT)
        .collect::<String>();

    // converts it to b64 so that it can be used in urls
    base64_url::encode(&token)
}

/// Serve index page
/// If the user is logged, add a anti-CSRF token to the password change form
pub async fn home(
    session: Session,
    user: Option<AccessUser>,
) -> axum::response::Result<impl IntoResponse> {
    trace!("Serving home");

    // Create anti-CSRF token if the user is logged
    let infos = match user {
        Some(user) => {
            debug!("Add anti-CSRF token to home");

            // Generate anti-CSRF token
            let token = Uuid::new_v4().to_string();
            let expiration = OffsetDateTime::now_utc() + Duration::minutes(10);

            // Add token+exp to session
            session.insert("csrf", token.clone()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
            session.insert("csrf_expiration", expiration.unix_timestamp()).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

            Some(json!({"email": user.email, "token": token}))
        }
        None => None, // Can't use user.map, async move are experimental
    };

    Ok(Html(HBS.render("index", &infos).unwrap()))
}

/// DEBUG/ADMIN endpoint
/// List pending emails to send
pub async fn email(Path(email): Path<String>) -> axum::response::Result<Json<Vec<Email>>> {
    let emails = database::email::get(&email).or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;
    Ok(emails.into())
}

pub async fn logout(jar: CookieJar) -> (CookieJar, Redirect) {
    let jar = jar.remove(Cookie::from("access"));
    (jar, Redirect::to("/"))
}

pub async fn login_page() -> impl IntoResponse {
    Html(HBS.render("login", &Some(())).unwrap())
}
