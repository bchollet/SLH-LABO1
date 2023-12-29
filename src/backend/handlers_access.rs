use axum::Json;
use http::StatusCode;
use log::info;
use tower_sessions::Session;

use crate::backend::middlewares::AccessUser;
use crate::backend::models::ChangePassword;
use crate::database::user;
use crate::utils::input_validation::{are_passwords_equals, is_password_valid};
use crate::utils::password::{checked_password, hash_password};

pub async fn change_password (
    session: Session,
    user: AccessUser,
    Json(parameters): Json<ChangePassword>
) -> axum::response::Result<StatusCode> {
    info!("Changing user's password");

    // Check that the anti-CSRF token isn't expired
    let token_expiration = session.get::<i64>("csrf_expiration").or(Err(StatusCode::INTERNAL_SERVER_ERROR))?.ok_or(StatusCode::BAD_REQUEST)?;
    if token_expiration < time::OffsetDateTime::now_utc().unix_timestamp() {
        info!("Anti-CSRF token expired");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF token expired"))?;
    }

    // Compare the anti-CSRF token saved with the given one
    let token = session.get::<String>("csrf")
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::BAD_REQUEST)?;
    if token != parameters.csrf {
        info!("Anti-CSRF tokens don't match");
        Err((StatusCode::BAD_REQUEST, "Anti-CSRF tokens don't match"))?;
    }

    // TODO : Check the parameters then update the DB with the new password
    if !are_passwords_equals(&parameters.password, &parameters.password2) {
        Err((StatusCode::BAD_REQUEST, "Passwords do not match"))?;
    }
    if !checked_password(&user.email, &parameters.old_password) {
        Err((StatusCode::BAD_REQUEST, "Old password is wrong"))?;
    }
    match is_password_valid(&parameters.password, 2) {
        Ok(_) => {
            let hash = hash_password(parameters.password.as_ref());
            if user::change_password(&user.email, &hash).unwrap_or(false) {
                return Ok(StatusCode::NO_CONTENT)
            }
        }
        Err(err) => {
            return Err((StatusCode::BAD_REQUEST, err))?
        }
    }
    Err((StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong"))?
}
