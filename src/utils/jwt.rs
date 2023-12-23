use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use log::info;
use sha2::Sha256;

#[derive(Debug)]
pub enum Role {
    Access,
    Refresh,
}

const SECRET_REFRESH: &str = "REFRESH";
const SECRET_ACCESS: &str = "ACCESS";
const TIME_LIMIT_REFRESH: u64 = 2 * 60 * 60;
const TIME_LIMIT_ACCESS: u64 = 5 * 60;

/// Verify the validity of a JWT accordingly to its role (access or refresh)
/// Return the email contained in the JWT if its valid
/// Return an error if the JWT is invalid
pub fn verify<T: Into<String>>(jwt: T, role: Role) -> Result<String> where String: From<T> {
    let token = String::from(jwt);
    info!("Verifying token with role {:?}", role);
    match role {
        Role::Access => {
            validate_and_get_mail(&token, TIME_LIMIT_ACCESS, SECRET_ACCESS)
        }
        Role::Refresh => {
            validate_and_get_mail(&token, TIME_LIMIT_REFRESH, SECRET_REFRESH)
        }
    }
}

pub fn set_jwt(role: Role, email: &str) -> String {
    info!("Setting token with role {:?}", role);
    match role {
        Role::Access => { generate(SECRET_ACCESS, email) }
        Role::Refresh => { generate(SECRET_REFRESH, email)}
    }
}

fn generate(secret : &str, email: &str) -> String {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_ref()).unwrap();
    let mut claims = BTreeMap::new();
    let start = SystemTime::now();
    let now = start.duration_since(UNIX_EPOCH).unwrap().as_secs().to_string();
    claims.insert("sub", email);
    claims.insert("iat", &now);
    info!("Token generated successfully");
    claims.sign_with_key(&key).unwrap()
}

fn validate_and_get_mail(jwt: &str, time_limit_in_sec: u64, secret: &str) -> Result<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_ref())?;
    let claims: BTreeMap<String, String> = jwt.verify_with_key(&key)?;
    info!("Token has been successfully verified");
    let iat = claims["iat"].parse()?;
    let email = claims["sub"].clone();
    if is_expired(iat, time_limit_in_sec) { return Err(anyhow!("Token has expired")); }
    Ok(String::from(email))
}

fn is_expired(iat_in_sec: u64, time_limit_in_sec: u64) -> bool {
    let start = SystemTime::now();
    let now_in_sec = start.duration_since(UNIX_EPOCH).unwrap().as_secs();
    iat_in_sec + time_limit_in_sec > now_in_sec
}
