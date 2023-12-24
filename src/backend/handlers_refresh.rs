use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::CookieJar;
use log::info;
use tower_sessions::cookie::SameSite;

use crate::backend::middlewares::RefreshUser;
use crate::utils::jwt::{Role, set_jwt};

pub async fn get_access(user: RefreshUser, jar: CookieJar) -> axum::response::Result<CookieJar> {
    info!("Get access JWT from refresh JWT");
    // User's refresh token is already checked through the extractor RefreshUser
    // You can trust the email given in the parameter "user"

    let jwt = set_jwt(Role::Access, &user.email); // TODO : Create access JWT for email in user
    info!("Got this: {jwt}");

    // Add JWT to jar
    let cookie = Cookie::build(("access", jwt))
        .http_only(true) //Avoid reading cookie through Javascript
        .secure(true) //Https mandatory for this cookie
        .same_site(SameSite::Strict) //Cookie must be on the same domain (prevent CSRF)
        // TODO : Optionally set cookie's parameters
        ;
    let jar = jar.add(cookie);

    Ok(jar)
}
