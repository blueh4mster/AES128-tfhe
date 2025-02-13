use super::constants::{SBOX};
use tfhe::prelude::*;
use tfhe::{
    FheUint16, FheUint8, MatchValues,
};

pub fn generate_match_table() -> MatchValues<u16> {
    let mut match_vec : Vec<(_, _)> = Vec::new();
    for i in 0..256{
        match_vec.push((i as u16, SBOX[i] as u16));
    }
    let match_values = MatchValues::new(match_vec).unwrap();
    match_values
}