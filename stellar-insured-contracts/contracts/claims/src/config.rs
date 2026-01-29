use soroban_sdk::{contracttype, Env};

#[contracttype]
pub struct Config {
    pub dispute_window_secs: u64,
}

pub fn get_config(env: &Env) -> Config {
    env.storage()
        .instance()
        .get(&"CONFIG")
        .unwrap_or(Config {
            dispute_window_secs: 86_400, // 24h default
        })
}
