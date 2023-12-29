use email_address::EmailAddress;
use zxcvbn::zxcvbn;

pub fn is_register_form_valid(email: &str, password: &str, password2: &str) -> Result<(), String> {
    if password != password2 {
        return Err(String::from("Passwords are not the same"))
    }
    is_email_valid(email).and(is_password_valid(password, 2))
}

pub fn is_login_form_valid(email: &str, password: &str) -> Result<(), String> {
    if is_email_valid(email).and(is_password_valid(password, 2)).is_err() {
        return Err(String::from("Incorrect email or password"))
    }
    Ok(())
}

pub fn is_email_valid(email: &str) -> Result<(), String> {
    if EmailAddress::is_valid(email) {
        return Ok(())
    }
    Err(String::from("Email is invalid"))
}

pub fn are_passwords_equals(password: &str, password2: &str) -> bool {
    password == password2
}

pub fn is_password_valid(password: &str, lower_bound: u8) -> Result<(), String> {
    if password.len() < 8 || password.len() > 64 {
        return Err(String::from("Password either too short or too long"));
    }
    // zxcvbn will return a score for the password passed in parameter
    let estimate = zxcvbn(password, &[]).unwrap().score();
    if estimate <= lower_bound {
        return Err(String::from("Password not strong enough"))
    }
    Ok(())
}