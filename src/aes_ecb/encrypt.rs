use super::expand::expand_keys;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint8, MatchValues,
};

pub fn encrypt(vi: &mut [FheUint8;16], key: &mut [FheUint8;16]){
    let mut state = *input;

    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let fhe_zero = FheUint8::encrypt(0u8, &client_key);

    let mut expanded_keys: [FheUint8;176] = std::array::from_fn(|_| fhe_zero.clone());
    expand_keys(&mut key, &mut expanded_keys);
}