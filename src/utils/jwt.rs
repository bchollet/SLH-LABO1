use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use anyhow::{anyhow, Result};
use dotenv::dotenv;
use hmac::{Hmac, Mac};
use jwt::{SignWithKey, VerifyWithKey};
use log::{info, warn};
use sha2::Sha256;

#[derive(Debug)]
pub enum Role {
    Access,
    Refresh,
}

const TIME_LIMIT_REFRESH: u128 = 2 * 60 * 60 * 1000; // 2 hours in milli
const TIME_LIMIT_ACCESS: u128 = 5 * 60 * 1000; // 5 min in milli

/// Verify the validity of a JWT accordingly to its role (access or refresh)
/// Return the email contained in the JWT if its valid
/// Return an error if the JWT is invalid
pub fn verify<T: Into<String>>(jwt: T, role: Role) -> Result<String> where String: From<T> {
    let token = String::from(jwt);
    info!("Verifying token with role {:?}", role);
    dotenv().ok();
    match role {
        Role::Access => {
            info!("Using secret {:?}", std::env::var("JWT_ACCESS_SECRET"));
            validate_and_get_mail(&token, TIME_LIMIT_ACCESS, &std::env::var("JWT_ACCESS_SECRET").unwrap())
        }
        Role::Refresh => {
            info!("Using secret {:?}", std::env::var("JWT_REFRESH_SECRET"));
            validate_and_get_mail(&token, TIME_LIMIT_REFRESH, &std::env::var("JWT_REFRESH_SECRET").unwrap())
        }
    }
}

pub fn set_jwt(role: Role, email: &str) -> String {
    info!("Setting token with role {:?}", role);
    dotenv().ok();
    match role {
        Role::Access => { generate(&std::env::var("JWT_ACCESS_SECRET").unwrap(), email) }
        Role::Refresh => { generate(&std::env::var("JWT_REFRESH_SECRET").unwrap(), email)}
    }
}

fn generate(secret : &str, email: &str) -> String {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_ref()).unwrap();
    let mut claims = BTreeMap::new();
    let start = SystemTime::now();
    let now = start.duration_since(UNIX_EPOCH).unwrap().as_millis().to_string();
    claims.insert("email", email);
    claims.insert("iat", &now);
    info!("Token generated successfully");
    claims.sign_with_key(&key).unwrap()
}

fn validate_and_get_mail(jwt: &str, time_limit: u128, secret: &str) -> Result<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_ref())?;
    let claims: BTreeMap<String, String> = jwt.verify_with_key(&key)?;
    info!("Token has been successfully verified");
    let iat = claims["iat"].parse()?;
    let email = claims["email"].clone();
    if is_expired(iat, time_limit) {
        warn!("Token has expired");
        return Err(anyhow!("Token has expired"));
    }
    info!("Value of token iat: {iat}, email: {email}");
    Ok(String::from(email))
}

fn is_expired(iat: u128, time_limit: u128) -> bool {
    let start = SystemTime::now();
    let now_in_sec = start.duration_since(UNIX_EPOCH).unwrap().as_millis();
    iat + time_limit < now_in_sec
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_verify_access_token() {
        env::set_var("JWT_ACCESS_SECRET", "your_access_secret");
        let email = "test@example.com";
        let token = set_jwt(Role::Access, email);
        let result = verify(token, Role::Access);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), email);
    }

    #[test]
    fn test_verify_refresh_token() {
        env::set_var("JWT_REFRESH_SECRET", "your_refresh_secret");
        let email = "test@example.com";
        let token = set_jwt(Role::Refresh, email);
        let result = verify(token, Role::Refresh);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), email);
    }

    #[test]
    fn test_verify_invalid_token() {
        env::set_var("JWT_ACCESS_SECRET", "your_access_secret");
        let invalid_token = "invalid_token";
        let result = verify(invalid_token, Role::Access);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_expired_token() {
        env::set_var("JWT_ACCESS_SECRET", "your_access_secret");
        let email = "test@example.com";
        let expired_token = generate("your_access_secret", email);

        // Simulate an expired token
        let expiration_time = SystemTime::now() - std::time::Duration::from_millis(TIME_LIMIT_ACCESS as u64 + 1000);
        let iat = expiration_time.duration_since(UNIX_EPOCH).unwrap().as_millis();
        let expired_token = generate_with_iat("your_access_secret", email, iat);

        let result = verify(expired_token, Role::Access);
        assert!(result.is_err());
    }

    fn generate_with_iat(secret: &str, email: &str, iat: u128) -> String {
        let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_ref()).unwrap();
        let mut claims = BTreeMap::new();
        claims.insert("email", email);
        let binding = iat.to_string();
        claims.insert("iat", &binding);
        claims.sign_with_key(&key).unwrap()
    }
}
