use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint8, MatchValues,
};

pub fn fhe_uint(a: u8) -> FheUint8 {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
    let fhe_uint = FheUint8::encrypt(a, &client_key);
    fhe_uint
}