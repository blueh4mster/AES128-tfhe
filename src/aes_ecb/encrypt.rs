use super::expand::{expand_keys, generate_match_table};
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint8, MatchValues,
};

pub fn sub_bytes(state : &mut [FheUint8;16]){
    let match_values = generate_match_table();
    for byte in state.iter_mut(){
        let (result, matched) = byte.match_values(&match_values).unwrap();
        let matched = matched.decrypt(&client_key);
        if matched{
            *byte = result;
        }
    }
}

/// aes encrypt cipher block
/// 1. generate round keys using key expansion
/// 2. perform 9 rounds of sub_bytes, shift_rows, mix_columns and add_blocks
/// 3. perform last round omitting mix_columns 

pub fn encrypt(vi: &mut [FheUint8;16], key: &mut [FheUint8;16]){
    let mut state = *input;

    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let fhe_zero = FheUint8::encrypt(0u8, &client_key);

    let mut expanded_keys: [FheUint8;176] = std::array::from_fn(|_| fhe_zero.clone());
    expand_keys(&mut key, &mut expanded_keys);
}