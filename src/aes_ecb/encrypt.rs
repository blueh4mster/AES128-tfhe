use super::expand::{expand_keys, generate_match_table};
use super::utils::fhe_uint;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint8, MatchValues
};


/// byte substitution

pub fn sub_bytes(state : &mut [FheUint8;16]){
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let match_values = generate_match_table();
    for byte in state.iter_mut(){
        let (result, matched) = byte.match_value(&match_values).unwrap();
        let matched = matched.decrypt(&client_key);
        if matched{
            *byte = result;
        }
    }
}

/// shift rows 
/// too much clone, need to figure out alternative solution

pub fn shift_rows(state : &mut [FheUint8;16]){
    
    let fhe_zero = fhe_uint(0u8);

    let mut temp: [FheUint8;16] = std::array::from_fn(|_| fhe_zero.clone());
    for i in 0..16 {
        temp[i] = state[i].clone();
    }

    // column 0
    state[0] = temp[0].clone();
    state[1] = temp[5].clone();
    state[2] = temp[10].clone();
    state[3] = temp[15].clone();

    // column 1
    state[4] = temp[4].clone();
    state[5] = temp[9].clone();
    state[6] = temp[14].clone();
    state[7] = temp[3].clone();

    // column 2
    state[8] = temp[8].clone();
    state[9] = temp[13].clone();
    state[10] = temp[2].clone();
    state[11] = temp[7].clone();

    // column 3
    state[12] = temp[12].clone();
    state[13] = temp[1].clone();
    state[14] = temp[6].clone();
    state[15] = temp[11].clone();
}

/// add blocks bitwise or operation on state and key

pub fn add_blocks(state: &mut [FheUint8;16], b: &mut [FheUint8; 16]){
    for j in 0..16{
        state[j] ^= b[j].clone();
    }
}

/// galios multiplication
pub fn galios_mul(a: FheUint8, b: FheUint8) -> FheUint8{
    let mut res: FheUint8 = fhe_uint(0u8);
    let mut a = a;
    let mut b = b;

    let ip: u8 = 0x1b;
    let irreducible_poly: FheUint8 = fhe_uint(ip);
    let fhe_one = fhe_uint(1u8);
    let c = fhe_uint(0x80);

    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);
    set_server_key(server_key);

    let match_values = MatchValues::new(vec![(0u8, 0u8)]).unwrap();

    loop {
        let (_, matched): (FheUint8, _) = b.clone().match_value(&match_values).unwrap();
        let matched = matched.decrypt(&client_key);
        if matched{
            break;
        }
        let temp = b.clone() & fhe_one.clone();
        let (_, matched): (FheUint8, _) = temp.match_value(&match_values).unwrap();
        let matched = matched.decrypt(&client_key);
        if matched{
            res ^= a.clone();
        }
        let temp_2 = a.clone() & c.clone();
        let (_, matched): (FheUint8, _) = temp_2.match_value(&match_values).unwrap();
        let matched = matched.decrypt(&client_key);
        if !matched {
            a ^= irreducible_poly.clone();
        }
        b >>= fhe_one.clone();
    }
    res
}

/// mix columns 

pub fn mix_columns(state: &mut [FheUint8;16]) {
}

/// aes encrypt cipher block
/// 1. generate round keys using key expansion
/// 2. perform 9 rounds of sub_bytes, shift_rows, mix_columns and add_blocks
/// 3. perform last round omitting mix_columns 

pub fn encrypt(vi: &mut [FheUint8;16], key: &mut [FheUint8;16]){
    let mut state = vi.clone();

    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);

    let fhe_zero = FheUint8::encrypt(0u8, &client_key);

    let mut expanded_keys: [FheUint8;176] = std::array::from_fn(|_| fhe_zero.clone());
    expand_keys(key, &mut expanded_keys);
}