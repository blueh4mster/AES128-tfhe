use super::constants::{SBOX, ROUND_CONSTS};
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint8, MatchValues,
};

pub fn generate_match_table() -> MatchValues<u8> {
    let mut match_vec : Vec<(_, _)> = Vec::new();
    for i in 0..256{
        match_vec.push((i as u8, SBOX[i] as u8));
    }
    let match_values = MatchValues::new(match_vec).unwrap();
    match_values
}

pub fn expand_keys(key: &[FheUint8;16], expanded_keys: &mut[FheUint8;176]){
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
    // copy the key elements to first 16 elements of expanded_keys
    // this is because the first key is the same as provided
    // cannot operate on a slice of expanded_keys therefore have to loop around from 0 to 16
    // too much use of clone(), need to figure out alternative

    for i in 0..16{
        expanded_keys[i] = key[i].clone();
    }

    let mut st = 16;

    let fhe_zero = FheUint8::encrypt(0u8, &client_key);
    let mut temp: [FheUint8;4] = std::array::from_fn(|_| fhe_zero.clone());

    while st < 176 {
        for k in 0..4{
            temp[k] = expanded_keys[st-4+k].clone();
        }

        if st % 16 == 0{
            // rotate left
            temp.rotate_left(1);
            // subtitute using SBOX and match_value
            for j in 0..4{
                let match_values = generate_match_table();
                let (result, matched) = temp[j].match_value(&match_values).unwrap();
                let matched = matched.decrypt(&client_key);
                if matched{
                    temp[j] = result;
                }
            }
            // xor
            // generate fhe encrypted round constant first
            let encrypted_round_const = FheUint8::encrypt(ROUND_CONSTS[st / 16], &client_key);
            // xor with encrypted round constant 
            temp[0] ^= encrypted_round_const;
        }

        for j in 0..4{
            expanded_keys[st] = &expanded_keys[st-16] ^ &temp[j];
            st += 1;
        }
    }
}   

