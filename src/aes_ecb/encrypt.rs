use super::expand::{expand_keys, generate_match_table};
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint8, MatchValues,
};

/// byte substitution

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

/// shift rows 

pub fn shift_rows(state : &mut [FheUint8;16]){
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let fhe_zero = FheUint8::encrypt(0u8, &client_key);

    let mut temp: [FheUint8;16] = std::array::from_fn(|_| fhe_zero.clone());
    temp.copy_from_slice(state);

    // column 0
    state[0] = temp[0];
    state[1] = temp[5];
    state[2] = temp[10];
    state[3] = temp[15];

    // column 1
    state[4] = temp[4];
    state[5] = temp[9];
    state[6] = temp[14];
    state[7] = temp[3];

    // column 2
    state[8] = temp[8];
    state[9] = temp[13];
    state[10] = temp[2];
    state[11] = temp[7];

    // column 3
    state[12] = temp[12];
    state[13] = temp[1];
    state[14] = temp[6];
    state[15] = temp[11];
}

/// add blocks bitwise or operation on state and key

pub fn add_blocks(state: &mut [FheUint8;16], b: &mut [FheUint8; 16]){
    for j in 0..16{
        state[j] ^= b[j];
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