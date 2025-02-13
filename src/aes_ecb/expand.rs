use super::constants::{SBOX};
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
    // copy_from_slice not supported for FheUint8 
    // try_into doesn't work because size of [FheUint<FheUint8Id>] not known at compile time
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
            // subtitute 
            // xor
        }

        for j in 0..4{
            expanded_keys[st] = &expanded_keys[st-16] ^ &temp[j];
            st += 1;
        }
    }

}   