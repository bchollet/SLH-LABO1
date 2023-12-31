use argon2::{Config, Variant, verify_encoded, Version};
use rand::Rng;
use crate::database::user::get;

const CONFIG: Config = Config {
    variant: Variant::Argon2id,
    version: Version::Version13,
    mem_cost: 10000,
    time_cost: 10,
    lanes: 4,
    secret: &[],
    ad: &[],
    hash_length: 32,
};

fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let salt: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();

    // Convert the salt bytes to a hexadecimal string
    let hex_string: String = salt.iter().map(|byte| format!("{:02x}", byte)).collect();

    hex_string
}

pub fn hash_password(password: &[u8]) -> String {
    let salt = generate_salt();
    argon2::hash_encoded(password, salt.as_ref(), &CONFIG).unwrap()
}

pub fn checked_password(email: &str, password: &str) -> bool {
    const DEFAULT_PASS: &str = "dedce41f-a89c-4f98-8107-ea26bc83752a";
    match get(&email) {
        None => {
            let _ = verify_encoded(DEFAULT_PASS, DEFAULT_PASS.as_ref());
            false
        }
        Some(user) => {
            verify_encoded(&user.hash, password.as_ref()).unwrap() && user.verified
        }
    }
}

// ------------------ UNIT TESTS --------------------------

#[cfg(test)]
mod tests {
    use mockall::{automock, mock};
    use mockall::predicate::eq;
    use crate::database::user::User;
    use super::*;

    // Mocking the get function
    #[automock]
    trait UserDatabase {
        fn get(&self, email: &str) -> Option<User>;
    }

    //In order to mock the get function, we use this function which is very similar to the prod one
    fn checked_password_with_database(database: &dyn UserDatabase, email: &str, password: &str) -> bool {
        const DEFAULT_PASS: &str = "dedce41f-a89c-4f98-8107-ea26bc83752a";
        match database.get(email) {
            None => {
                let _ = verify_encoded(DEFAULT_PASS, DEFAULT_PASS.as_ref());
                false
            }
            Some(user) => {
                verify_encoded(&user.hash, password.as_ref()).unwrap() && user.verified
            }
        }
    }

    #[test]
    fn test_generate_salt() {
        // Test that the generated salt has the correct length
        let salt = generate_salt();
        assert_eq!(salt.len(), 32);  // 16 bytes converted to a 32-character hexadecimal string
    }

    #[test]
    fn test_hash_password() {
        // Test that hash_password produces a non-empty string
        let password = b"my_password";
        let hashed_password = hash_password(password);
        let hashed_password2 = hash_password(password);
        assert!(!hashed_password.is_empty());
        // The same password should have a different hash
        assert_ne!(hashed_password, hashed_password2);
    }

    #[test]
    fn test_checked_password() {
        // Test case when the user is not found (None)
        assert!(!checked_password("nonexistent@example.com", "password"));

        // Test case when the user is found (Some)
        let email = "existing@example.com";
        let password = "correct_password";
        let hash = hash_password(password.as_bytes());
        // Create a mock instance of UserDatabase
        let mut mock_database = MockUserDatabase::new();

        // Configure the mock to return a user with the correct hash and verification status
        mock_database
            .expect_get()
            .with(eq(email))
            .returning(move |_| Some(User {
                hash: hash.clone(),
                verified: true,
            }));

        // Correct password and verified user
        assert!(checked_password_with_database(&mock_database, email, password));

        // Incorrect password, but user is verified
        assert!(!checked_password_with_database(&mock_database, email, "incorrect_password"));

        let hash = hash_password(password.as_bytes());
        let mut mock_database = MockUserDatabase::new();
        mock_database
            .expect_get()
            .with(eq(email))
            .returning(move |_| Some(User {
                hash: hash.clone(),
                verified: false,
            }));

        // Correct password, but user is not verified
        assert!(!checked_password_with_database(&mock_database, email, password));
    }
}