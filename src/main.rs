/* 
* Estas funciones utilizan la biblioteca ring para realizar la derivación de clave usando PBKDF2 con 
* el algoritmo HMAC_SHA512. La función encrypt toma una contraseña y una sal como entrada, y devuelve 
* el resultado de la encriptación como un arreglo de bytes de longitud fija de 64 bytes. La función 
* verify toma un resultado de encriptación previo, una contraseña y una sal como entrada, y verifica 
* si la contraseña coincide con el resultado de encriptación proporcionado. Ambas funciones utilizan 
* un número fijo de iteraciones (100,000) para la derivación de clave, y utilizan la misma longitud 
* de salida (64 bytes) para el resultado de encriptación.
*/

use data_encoding::HEXUPPER;
use ring::{digest, pbkdf2};
use std::{num::NonZeroU32, env};

const CREDENTIAL_LEN: usize = digest::SHA512_OUTPUT_LEN;

// Función para encriptar una contraseña usando PBKDF2 con algoritmo HMAC_SHA512
fn encrypt(password: &str, salt: &str) -> [u8; 64] {
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let mut pbkdf2_hash = [0u8; CREDENTIAL_LEN];

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt.as_bytes(),
        password.as_bytes(),
        &mut pbkdf2_hash,
    );
    return pbkdf2_hash;
}

// Función para verificar si una contraseña coincide con un resultado de encriptación previo
fn verify(result: [u8; CREDENTIAL_LEN], password: &str, salt: &str) -> bool {
    let n_iter = NonZeroU32::new(100_000).unwrap();
    let pbkdf2_hash = result;

    let should_succeed = pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA512,
        n_iter,
        &salt.as_bytes(),
        password.as_bytes(),
        &pbkdf2_hash,
    );

    return should_succeed.is_ok();
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let password: &str = args[1].as_str();
    let salt: &str = args[2].as_str();
    let result = encrypt(password, salt);
    println!("Encrypted password: {}", HEXUPPER.encode(&result));
    println!("Matching password {}", verify(result, password, salt));
}


    //println!("Salt: {}", HEXUPPER.encode(&salt.as_bytes()));
    //println!("PBKDF2 hash: {}", HEXUPPER.encode(&pbkdf2_hash));

    // let should_succeed = pbkdf2::verify(
    //     pbkdf2::PBKDF2_HMAC_SHA512,
    //     n_iter,
    //     &salt.as_bytes(),
    //     password.as_bytes(),
    //     &pbkdf2_hash,
    // );
    // let wrong_password = "Definitely not the correct password";
    // let should_fail = pbkdf2::verify(
    //     pbkdf2::PBKDF2_HMAC_SHA512,
    //     n_iter,
    //     &salt.as_bytes(),
    //     wrong_password.as_bytes(),
    //     &pbkdf2_hash,
    // );

    // println!("{}",should_succeed.is_ok());
    // println!("{}",!should_fail.is_ok());