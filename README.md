# Encryption in rust
* These functions use the ring library to perform key derivation using PBKDF2 with the HMAC_SHA512 algorithm. 
* The encrypt function takes a password and a salt as input, and returns the result of encryption as a 64-byte 
* fixed-length byte array. The function verify takes a previous encryption result, a password and a salt as 
* input, and verifies if the password matches the provided encryption result. Both functions use a fixed number 
* of iterations (100,000) for key derivation, and they use the same length output (64 bytes) for the encryption result.
