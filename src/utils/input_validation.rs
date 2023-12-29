use zxcvbn::zxcvbn;
use regex::Regex;

pub const PASS_MIN_SIZE: usize = 8;
pub const PASS_MAX_SIZE: usize = 64;

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
    let regex_str = r"^(?=.{1,256}$)[a-zA-Z0-9_+&*-]{1,63}(?:\.[a-zA-Z0-9_+&*-]+){0,63}@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$";
    let regex = Regex::new(regex_str).unwrap();
    if regex.is_match(email) {
        return Ok(())
    }
    Err(String::from("Email is invalid"))
}

pub fn is_short_text_length_valid(input: &str, lower_bound: usize, upper_bound: usize) -> Result<(), String> {
    if input.chars().count() > upper_bound {
        return Err(String::from("is too long"))
    }
    if input.chars().count() < lower_bound {
        return Err(String::from("is too short"))
    }
    Ok(())
}

pub fn are_passwords_equals(password: &str, password2: &str) -> bool {
    password == password2
}

pub fn is_password_valid(password: &str, score_lower_bound: u8) -> Result<(), String> {
    match is_short_text_length_valid(password, PASS_MIN_SIZE, PASS_MAX_SIZE) {
        Err(err) => {
            return Err(format!("Password {err}"))
        }
        Ok(_) => {
            // zxcvbn will return a score for the password passed in parameter
            let estimate = zxcvbn(password, &[]).unwrap().score();
            if estimate <= score_lower_bound {
                return Err(String::from("Password not strong enough"))
            }
            Ok(())
        }
    }
}