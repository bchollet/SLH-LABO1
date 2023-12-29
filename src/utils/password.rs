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