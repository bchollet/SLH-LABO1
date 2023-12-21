use email_address::EmailAddress;
use zxcvbn::zxcvbn;

pub fn is_email_valid(email: &str) -> bool {
    return EmailAddress::is_valid(email)
}

pub fn is_password_secure(password: &str, lower_bound: u8) -> bool {
    if password.len() < 8 || password.len() > 64 {
        return false;
    }
    // zxcvbn will return a score for the password passed in parameter
    let estimate = zxcvbn(password, &[]).unwrap().score();
    estimate > lower_bound
}