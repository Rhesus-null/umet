use age::secrecy::SecretString;
use argh::FromArgs;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::{env, fs};

/// Tool for folder encryption written in Rust! (=^ ◡ ^=)
#[derive(FromArgs)]
struct MainCmd {
    /// the target into the folder you want to encrypt.
    #[argh(positional)]
    target: PathBuf,
    /// reverse the tool functionality from encrypting folder to decrypting one.
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
    if !args.target.is_dir(){
        eprintln!("'{}' is not a directory", target_path.display());
        return;
    }

    let name = Path::new(target_path.file_name().unwrap_or(OsStr::new("default"))).with_extension("tar.gz.age");
    let output_path = &args.output_path.unwrap_or(env::current_dir().unwrap()).join(name);
    let mut tar_gz = Cursor::new(Vec::new());
    let mut builder = tar::Builder::new(&mut tar_gz);
    builder.follow_symlinks(false);

    let ar =builder.append_dir_all("", target_path);
    if ar.is_err() {
        eprintln!("Error writing tar archive: {}", ar.unwrap_err());
    }
    let ir = builder.into_inner();
    if ir.is_err() {
        eprintln!("Error writing tar archive: {}", ir.unwrap_err());
    }


    let passphrase = confirm_password("[Encrypt]");
    let passphrase = SecretString::from(passphrase);


    let recipient = age::scrypt::Recipient::new(passphrase);
    let encrypted = age::encrypt(&recipient, tar_gz.into_inner().as_slice());
    if let Err(e) = encrypted {
        eprintln!("Error encrypting file: {}", e);
    } else {
        let encrypted = encrypted.unwrap();
        fs::write(output_path, encrypted).unwrap();
    }
}

fn decrypt_mode(args: MainCmd) {
    let target_path = &args.target;
    let output_path = &args.output_path.unwrap_or(env::current_dir().unwrap()).join(&rse(target_path, &["tar", "gz", "age"]).file_name().unwrap_or(OsStr::new("default")));
    if !target_path.exists() {
        fs::create_dir(output_path).unwrap();
    }
    let read = unsafe {memmap2::Mmap::map(&File::open(target_path).unwrap())};
    if let Err(e) = read {
        eprintln!("Error reading file: {}", e);
    } else {
        let passphrase = rpassword::prompt_password("[Decrypt] Type Password: ").unwrap();
        let passphrase = SecretString::from(passphrase);
        let identity = age::scrypt::Identity::new(passphrase);
        let decrypted = age::decrypt(&identity, &read.unwrap());
        if let Err(e) = decrypted {
            eprintln!("Error encrypting file: {}", e);
        } else {
            let decrypted = decrypted.unwrap();
            let mut archive = tar::Archive::new(&*decrypted);
            archive.unpack(output_path).unwrap();
        }
    }
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