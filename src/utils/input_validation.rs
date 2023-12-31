use zxcvbn::zxcvbn;
use regex::Regex;

pub const PASS_MIN_SIZE: usize = 8;
pub const PASS_MAX_SIZE: usize = 64;
pub const USERNAME_MAX_SIZE: usize = 63;
pub const EMAIL_MAX_SIZE: usize = 256;

pub fn is_register_form_valid(email: &str, password: &str, password2: &str) -> Result<(), String> {
    if !are_passwords_equals(&password, &password2) {
        return Err(String::from("Passwords are not the same"));
    }
    is_email_valid(email).and(is_password_valid(password, 2))
}

pub fn is_login_form_valid(email: &str, password: &str) -> Result<(), String> {
    if is_email_valid(email).and(is_password_valid(password, 2)).is_err() {
        return Err(String::from("Incorrect email or password"));
    }
    Ok(())
}

pub fn is_email_valid(email: &str) -> Result<(), String> {
    let regex_str = r"^[a-zA-Z0-9_+&*-]+(?:\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,7}$";
    let regex = Regex::new(regex_str).unwrap();
    let parts: Vec<&str> = email.splitn(2, '@').collect();
    if regex.is_match(email) && parts[0].chars().count() <= USERNAME_MAX_SIZE && email.chars().count() <= EMAIL_MAX_SIZE {
        return Ok(());
    }
    Err(String::from("Email is invalid"))
}

pub fn is_short_text_length_valid(input: &str, lower_bound: usize, upper_bound: usize) -> Result<(), String> {
    if lower_bound >= upper_bound {
        return Err(String::from("Wrong usage: Lower bound must be lesser than upper bound"));
    }
    if input.chars().count() > upper_bound {
        return Err(String::from("is too long"));
    }
    if input.chars().count() < lower_bound {
        return Err(String::from("is too short"));
    }
    Ok(())
}

pub fn are_passwords_equals(password: &str, password2: &str) -> bool {
    password == password2
}

pub fn is_password_valid(password: &str, score_lower_bound: u8) -> Result<(), String> {
    match is_short_text_length_valid(password, PASS_MIN_SIZE, PASS_MAX_SIZE) {
        Err(err) => {
            return Err(format!("Password {err}"));
        }
        Ok(_) => {
            // zxcvbn will return a score for the password passed in parameter
            let estimate = zxcvbn(password, &[]).unwrap().score();
            if estimate <= score_lower_bound {
                return Err(String::from("Password not strong enough"));
            }
            Ok(())
        }
    }
}

// ------------------ UNIT TESTS --------------------------

#[cfg(test)]
mod tests {
    use crate::utils::input_validation::{are_passwords_equals, is_email_valid, is_password_valid, is_short_text_length_valid};

    #[test]
    fn are_password_equals_returns_true_if_equals() {
        //Given
        let pass1 = String::from("Pa$$sw0rd");
        let pass2 = String::from("Pa$$sw0rd");
        //When
        let result = are_passwords_equals(&pass1, &pass2);
        //Then
        assert_eq!(result, true)
    }

    #[test]
    fn are_password_equals_returns_false_if_not_equals() {
        //Given
        let pass1 = String::from("Pa$$sw0rd");
        let pass2 = String::from("toto");
        //When
        let result = are_passwords_equals(&pass1, &pass2);
        //Then
        assert_eq!(result, false)
    }

    #[test]
    fn is_short_text_length_valid_returns_ok_if_length_valid() {
        //Given
        let lb = 8;
        let ub = 64;
        let input = String::from("I am supposed to be valid");
        //When
        let result = is_short_text_length_valid(&input, lb, ub);
        //Then
        assert_eq!(result, Ok(()))
    }

    #[test]
    fn is_short_text_length_valid_returns_err_if_wrong_usage() {
        //Given
        let lb = 64;
        let ub = 8;
        let input = String::from("Whatever");
        //When
        let result = is_short_text_length_valid(&input, lb, ub);
        //Then
        assert_eq!(result, Err(String::from("Wrong usage: Lower bound must be lesser than upper bound")))
    }

    #[test]
    fn is_short_text_length_valid_returns_err_if_length_invalid() {
        //Given
        let lb = 8;
        let ub = 64;
        let input = "Invalid";
        let input2 = "Yay, I am also invalid, but this time it is because I am too long";
        //When
        let result = is_short_text_length_valid(input, lb, ub);
        let result2 = is_short_text_length_valid(input2, lb, ub);
        //Then
        assert_eq!(result, Err(String::from("is too short")));
        assert_eq!(result2, Err(String::from("is too long")));
    }

    #[test]
    fn is_password_valid_returns_ok_if_valid() {
        //Given
        let pass = "Argent1234!";
        let pass2 = "4a-hSb_nf@°sd#jkBf";
        let pass3 = "a4Jlp$qwz";
        //When
        let result = is_password_valid(pass, 2);
        let result2 = is_password_valid(pass2, 2);
        let result3 = is_password_valid(pass3, 2);
        //Then
        assert_eq!(result, Ok(()));
        assert_eq!(result2, Ok(()));
        assert_eq!(result3, Ok(()));
    }

    #[test]
    fn is_password_valid_returns_err_if_length_invalid() {
        //Given
        let pass = "short";
        let pass2 = "Waaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay too long";
        //When
        let result = is_password_valid(pass, 2);
        let result2 = is_password_valid(pass2, 2);
        //Then
        assert_eq!(result, Err(String::from("Password is too short")));
        assert_eq!(result2, Err(String::from("Password is too long")));
    }

    #[test]
    fn is_password_valid_returns_err_if_not_strong_enough() {
        //Given
        let pass = "ArthurDent1";
        let pass2 = "Platypus";
        let pass3 = "egj@as?!";
        //When
        let result = is_password_valid(pass, 2);
        let result2 = is_password_valid(pass2, 2);
        let result3 = is_password_valid(pass3, 2);
        //Then
        assert_eq!(result, Err(String::from("Password not strong enough")));
        assert_eq!(result2, Err(String::from("Password not strong enough")));
        assert_eq!(result3, Err(String::from("Password not strong enough")));
    }

    #[test]
    fn is_email_valid_returns_ok_if_valid() {
        //Given
        let email = "a@a.aa"; //bare minimum
        let email2 = "user+sub.address@example.org"; //with sub address
        let email3 = "_+&*-._+&*-@1.aa"; //all special char
        let email4 = "192.168.1.1@10.10.0.5.ch"; //IP address
        let expected = Ok(());
        //When
        let result = is_email_valid(email);
        let result2 = is_email_valid(email2);
        let result3 = is_email_valid(email3);
        let result4 = is_email_valid(email4);
        //Then
        assert_eq!(result, expected);
        assert_eq!(result2, expected);
        assert_eq!(result3, expected);
        assert_eq!(result4, expected);
    }
    #[test]
    fn is_email_valid_returns_err_if_invalid() {
        //Given
        let email = "toto"; //wrong format
        let email2 = "a@a.a"; //last part invalid
        let email3 = "éàè@()<>''.ch"; //invalid special char
        let email4 = "qwertzuioplkjhgfdsayxcvbnmqwertzuiopasdfghjklyxcvbnm012345678910@a.com"; //first part too long
        let email5 = "qwertzuioplkjhgfdsayxcvbnmqwertzuiopasdfghjklyxcvbnm012345678910@sahbdfkjsdghfjksdhbfgkjsdnflkdsfjksdnfjksdbfjksdbfjsdbjfsdjkbfkjsdfbjksba.com"; //whole string too long
        let expected = Err(String::from("Email is invalid"));
        //When
        let result = is_email_valid(email);
        let result2 = is_email_valid(email2);
        let result3 = is_email_valid(email3);
        let result4 = is_email_valid(email4);
        let result5 = is_email_valid(email5);
        //Then
        assert_eq!(result, expected);
        assert_eq!(result2, expected);
        assert_eq!(result3, expected);
        assert_eq!(result4, expected);
        assert_eq!(result5, expected);
    }
}