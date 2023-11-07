pub use concrete_boolean::{ gen_keys, 
                            server_key::*,
                            ciphertext::*,
                            client_key::* };

pub use concrete_lib::CryptoAPIError;

pub const N_BITS_PER_CHAR: usize = 8;

fn main() {

    let (sk, pk) = gen_keys();

    println!("generated");
    let string = "abc".to_string();
    let sub_str = "a".to_string();

    let string_enc = str_to_enc_vec(&sk, &string);
    let sub_str_enc = str_to_enc_vec(&sk, &sub_str);


    println!("encrypted");

    let word_found_enc = search_sub(&pk, &sub_str_enc, &string_enc).unwrap();

    let result = sk.decrypt(&word_found_enc);

    println!("{}", result);
}

fn str_to_enc_vec(sk: &ClientKey, plaintext: &str) -> Vec<Ciphertext> {
    let plaintext_bytes = plaintext.as_bytes();

    let mut result = Vec::<Ciphertext>::new();

    for x in plaintext_bytes {

        for i in 0..N_BITS_PER_CHAR {
            if *x & (1 << i) != 0 {
                result.push(sk.encrypt(true))
            } else {
                result.push(sk.encrypt(false))
            }
        }
    }

    result
}





// this is copied from website
/// a custom error for FHE operations
#[derive(Debug, Clone)]
pub struct FHEError {
    message: String
}

impl FHEError {
    /// creates a new [`FHEError`]
    pub fn new(message: String) -> FHEError {
        FHEError { message }
    }
}

// implement the `Display` trait to be able to print the error
impl std::fmt::Display for FHEError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "FHEError: {}", self.message)
    }
}

// implement the `Error` trait
impl std::error::Error for FHEError {}

// convert Concrete's [`CryptoAPIError`] to an `FHEError`
impl std::convert::From<CryptoAPIError> for FHEError {
    fn from (err: CryptoAPIError) -> Self {
        FHEError::new(format!("CryptoAPIError: {:}", err))
    }
}







fn bits_are_equal(pk: &ServerKey, a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    pk.xnor(a, b)
}

// checks if the two sequences of bites is identical
fn are_equal(pk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext]) -> Result<Ciphertext, FHEError> {
    if a.len() == 0 {
        return Err(FHEError::new("Error checking the equality: the size of the first element is 0".to_string()));
    }

    if a.len() != b.len() {
        return Err(FHEError::new("Error checking the equality: the sizes are different".to_string()));
    }

    let mut are_equal = bits_are_equal(pk, &a[0], &b[0]);

    // we AND the result of XNORing all of the bits we are comparing so that we are only left with
    // 1 iff all of them are identical
    for i in 1..a.len() {
        are_equal = pk.and(&are_equal, &bits_are_equal(pk, &a[i], &b[i]));
    }

    Ok(are_equal)
}

// this function searches for occurences of b in a
fn search_sub(pk: &ServerKey, a: &[Ciphertext], b: &[Ciphertext]) -> Result<Ciphertext, FHEError> {
    if a.len() == 0 {
        return Err(FHEError::new("Error, length of a is 0".to_string()));
    }

    if b.len() < a.len() {
        return Ok(pk.and(&a[0], &pk.not(&a[0])));
    }

    let mut is_found = are_equal(pk, a, &b[..a.len()])?;
    let truth = pk.trivial_encrypt(true);
    let result = pk.trivial_encrypt(0);

    for i in 1..=(b.len()-a.len())/N_BITS_PER_CHAR {
        is_found = pk.or(&is_found, &are_equal(pk, a, &b[i*N_BITS_PER_CHAR..a.len()+i*N_BITS_PER_CHAR])?);
        result = result + pk.and(&is_found, &truth);
    }


    Ok(result)
}
