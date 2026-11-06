use age::secrecy::SecretString;
use argh::FromArgs;
use flate2::Compression;
use std::ffi::OsStr;
use std::fs::File;
use std::io::{Cursor, ErrorKind};
use std::path::{Path, PathBuf};
use std::{env, fs};
use tar::Archive;

/// Tool for folder/file encryption written in Rust! (=^ ◡ ^=)
#[derive(FromArgs)]
struct MainCmd {
    /// the target into the folder/file you want to encrypt.
    #[argh(positional)]
    target: PathBuf,
    /// reverse the tool functionality from encrypting folder/file to decrypting one.
    #[argh(switch, short = 'r')]
    reverse: bool,
    /// path to output the result.
    #[argh(option, short = 'o')]
    output_path: Option<PathBuf>,
}

fn main() {
    let args: MainCmd = argh::from_env();
    if !args.reverse {
        encrypt_mode(args)
    } else {
        decrypt_mode(args)
    }
}

fn encrypt_mode(args: MainCmd) {
    let target_path = &args.target;
    if !target_path.is_dir() {
        encrypt_single(args);
        return;
    }
    let output_path = get_output(args.output_path, target_path, &[]).with_extension("tar.gz.age");
    let mut encoder = flate2::write::GzEncoder::new(Cursor::new(Vec::new()), Compression::default());
    let mut builder = tar::Builder::new(&mut encoder);
    builder.follow_symlinks(false);

    let ar =builder.append_dir_all("", target_path);
    if ar.is_err() {
        eprintln!("Error writing tar archive: {}", ar.unwrap_err());
        return;
    }
    let ir = builder.into_inner();
    if ir.is_err() {
        eprintln!("Error writing tar archive: {}", ir.unwrap_err());
        return;
    }

    let passphrase = confirm_password("[Encrypt]");
    let passphrase = SecretString::from(passphrase);


    let recipient = age::scrypt::Recipient::new(passphrase);
    let encrypted = age::encrypt(&recipient, encoder.finish().unwrap().into_inner().as_slice());
    if let Err(e) = encrypted {
        eprintln!("Error encrypting file: {}", e);
        return;
    } else {
        let encrypted = encrypted.unwrap();
        fs::write(output_path, encrypted).unwrap();
    }
}

fn encrypt_single(args: MainCmd) {
    let target_path = &args.target;
    let output_path = get_output(args.output_path, target_path, &[]).with_extension("age");

    let read = unsafe {memmap2::Mmap::map(&File::open(target_path).unwrap())};
    if let Err(e) = read {
        eprintln!("Error reading file: {}", e);
    } else {
        let passphrase = confirm_password("[Encrypt]");
        let passphrase = SecretString::from(passphrase);


        let recipient = age::scrypt::Recipient::new(passphrase);
        let encrypted = age::encrypt(&recipient, &read.unwrap());
        if let Err(e) = encrypted {
            eprintln!("Error encrypting file: {}", e);
            return;
        } else {
            let encrypted = encrypted.unwrap();
            fs::write(output_path, encrypted).unwrap();
        }
    }
}

fn decrypt_mode(args: MainCmd) {
    let target_path = &args.target;
    let output_path = &get_output(args.output_path, target_path, &["tar", "gz", "age"]);
    let read = unsafe {memmap2::Mmap::map(&File::open(target_path).unwrap())};
    if let Err(e) = read {
        eprintln!("Error reading file: {}", e);
    } else {
        let passphrase = rpassword::prompt_password("[Decrypt] Type Password: ").unwrap();
        let passphrase = SecretString::from(passphrase);
        let identity = age::scrypt::Identity::new(passphrase);
        let decrypted = age::decrypt(&identity, &read.unwrap());
        if let Err(e) = decrypted {
            eprintln!("Error decrypting file: {}", e);
        } else {
            let mut decrypted = Cursor::new(decrypted.unwrap());

            let decoder = flate2::read::GzDecoder::new(&mut decrypted);
            let mut archive = Archive::new(decoder);
            if let Err(e) = archive.unpack(&output_path) {
                if e.kind() == ErrorKind::InvalidInput {
                    if output_path.exists() {
                        fs::remove_dir(output_path).unwrap();
                    }
                    fs::write(rse(output_path, &["age"]), decrypted.into_inner()).unwrap();
                } else {
                    eprintln!("Error decrypting file: {}", e);
                }
            }
        }
    }
}

fn get_output(output_path: Option<PathBuf>, target_path: &Path, remove_extension: &[&str]) -> PathBuf {
    if output_path.is_none() {
        let current_dir = env::current_dir();
        if let Ok(current_dir) = current_dir {
            return current_dir.join(&rse(target_path, remove_extension).file_name().unwrap_or(OsStr::new("default")))
        } else {
            panic!("Error getting current directory: '{}'", current_dir.unwrap_err());
        }
    }
    output_path.unwrap().to_path_buf()
}

fn rse<P: AsRef<Path>>(path: P, extensions_to_remove: &[&str]) -> PathBuf {
    let path = path.as_ref();
    let mut file_name = match path.file_name().and_then(|os_str| os_str.to_str()) {
        Some(name) => name.to_string(),
        None => return path.to_path_buf(),
    };

    let suffix_to_remove: String = extensions_to_remove
        .iter()
        .map(|ext| format!(".{}", ext.trim_start_matches('.')))
        .collect();

    if file_name.ends_with(&suffix_to_remove) {
        let new_len = file_name.len() - suffix_to_remove.len();
        file_name.truncate(new_len);

        if let Some(parent) = path.parent() {
            return parent.join(file_name);
        }
        return PathBuf::from(file_name);
    }

    path.to_path_buf()
}
fn confirm_password(prefix: &'static str) -> String {
    let password = rpassword::prompt_password(format!("{} Type Password: ", prefix)).unwrap();
    let mut retyped = rpassword::prompt_password(format!("{} Retype Password: ", prefix)).unwrap();

    while !(retyped == password) {
        println!("password mismatch");
        retyped = rpassword::prompt_password(format!("{} Retype Password: ", prefix)).unwrap();
    }
    password
}