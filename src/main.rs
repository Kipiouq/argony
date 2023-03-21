use core::fmt;

use argon2::Config;

const OPTIONS: &str = "encrypt\ncompare\ncheck";
fn main() {
    let args = args();

    if args.len() < 2 {
        println!("{OPTIONS}");
        return;
    };

    let res = match args[1].as_str() {
        "encrypt" => cli_encrypt(),
        "compare" => cli_compare(),
        "check" => check(),
        _ => String::from(OPTIONS),
    };

    println!("{res}");
}

fn cli_compare() -> String {
    println!("text one");
    let string = input();
    println!("text two");
    let hash = input();

    { string == hash }.to_string()
}

fn cli_encrypt() -> String {
    println!("enter target string");
    let string = input();

    match encrypt(&string) {
        Ok(a) => a,
        Err(a) => a.to_string(),
    }
}

fn check() -> String {
    println!("give original");

    let string = input();
    println!("give hash");
    let hash = input();

    { encrypt(&string).unwrap() == hash }.to_string()
}

pub fn encrypt(password: &str) -> Result<String, EnErr> {
    let password = password.as_bytes();

    let salt = match std::fs::read("salt.txt") {
        Ok(a) => a,
        Err(e) => return Err(EnErr::Fs(e.to_string())),
    };

    let config = Config::default();
    let hash = match argon2::hash_encoded(password, &salt, &config) {
        Ok(a) => a,
        Err(e) => return Err(EnErr::Hash(e.to_string())),
    };

    match argon2::verify_encoded(&hash, password) {
        Ok(true) => Ok(hash),
        Ok(false) => Err(EnErr::Verify(String::from("Failed validation: no match"))),
        Err(e) => Err(EnErr::Verify(e.to_string())),
    }
}
#[derive(Debug)]
pub enum EnErr {
    Fs(String),
    Verify(String),
    Hash(String),
}

fn args() -> Vec<String> {
    let mut vec = Vec::new();
    for x in std::env::args() {
        vec.push(x)
    }
    vec
}

impl fmt::Display for EnErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let str = match self {
            EnErr::Fs(a) => format!("Filesystem error: {a}"),
            EnErr::Verify(a) => format!("Hash verification error: {a}"),
            EnErr::Hash(a) => format!("Hashing error: {a}"),
        };
        write!(f, "{str}")
    }
}

fn input() -> String {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    let input = input.trim();
    String::from(input)
}
