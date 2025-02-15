use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint8, MatchValues,
};

pub fn fhe_zero() -> FheUint8 {
    let config = ConfigBuilder::default().build();

    let (client_key, server_key) = generate_keys(config);

    set_server_key(server_key);
    let fhe_zero = FheUint8::encrypt(0u8, &client_key);
    fhe_zero
}