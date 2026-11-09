use age::secrecy::SecretString;
use argh::FromArgs;
use flate2::Compression;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Cursor;
use std::path::{Component, Path, PathBuf};
use std::{env, fs};
use std::os::unix::ffi::OsStrExt;
use tar::Archive;

/// ultimate minimal encryption tool or umet is a tool for file or folder encryption! (=^ ◡ ^=)
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
    let mut output_path = get_output(args.output_path, target_path);
    if !target_path.exists() {
        eprintln!("path: \"{}\" doesn't exist ", target_path.display());
        return;
    }
    if target_path.is_dir() {
        output_path.add_extension("tar.gz.age");

        let mut encoder = flate2::write::GzEncoder::new(Cursor::new(Vec::new()), Compression::best());
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
        if let Ok(r) = encoder.finish() {
            prompt_encryption(&*r.into_inner(), &output_path)
        }
    } else {
        let result = unsafe { &*(memmap2::Mmap::map(&File::open(target_path).unwrap()).unwrap()) };
        output_path.add_extension("age");
        prompt_encryption(result, &output_path)
    }
}

fn prompt_encryption(r: &[u8], out: &Path) {
    let passphrase = confirm_password("[Encrypt]");
    let passphrase = SecretString::from(passphrase);

    let recipient = age::scrypt::Recipient::new(passphrase);
    let encrypted = age::encrypt(&recipient, r);
    if let Err(e) = encrypted {
        eprintln!("Error encrypting file: {}", e);
        return;
    } else {
        let encrypted = encrypted.unwrap();
        fs::write(out, encrypted).unwrap();
    }
}

fn decrypt_mode(args: MainCmd) {
    let target_path = &args.target;
    let mut output_path = get_output(args.output_path, target_path);
    if !target_path.exists() {
        eprintln!("path: \"{}\" doesn't exist ", target_path.display());
        return;
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
            eprintln!("Error decrypting file: {}", e);
        } else {
            let decrypted = decrypted.unwrap();
            if infer::is_archive(&decrypted) {
                remove_extension(&mut output_path, [b"tar", b"gz", b"age"]);
                let mut decrypted = Cursor::new(decrypted);

                let decoder = flate2::read::GzDecoder::new(&mut decrypted);
                let mut archive = Archive::new(decoder);
                if let Err(e) = archive.unpack(&output_path) {
                    eprintln!("Error unpacking file: {}", e);
                }
            } else {
                remove_extension(&mut output_path, [b"age"]);
                if let Err(e) = fs::write(output_path, decrypted) {
                    eprintln!("Error writing file: {}", e);
                }
            }
        }
    }
}

fn get_output(output_path: Option<PathBuf>, target_path: &Path) -> PathBuf {
    if output_path.is_none() {
        let current_dir = env::current_dir();
        if let Ok(current_dir) = current_dir {
            return current_dir.join(&target_path.file_name().unwrap_or(OsStr::new("default")))
        } else {
            panic!("Error getting current directory: '{}'", current_dir.unwrap_err());
        }
    }
    let o = output_path.unwrap().to_path_buf();
    if let Some(c) = o.components().last() {
        return match c {
            Component::Normal(_) => o,
            Component::RootDir | Component::ParentDir | Component::CurDir => {
                o.join(&target_path.file_name().unwrap_or(OsStr::new("default")))
            }
            Component::Prefix(_) => {
                #[cfg(target_os = "windows")]
                {
                    panic!("This tool is only available for Linux, therefore path \"{}\" is unsupported", o);
                }
                panic!("Unsupported output path: {:?}", o);
            }
        }
    }
    o
}

fn remove_extension<const N: usize>(path: &mut PathBuf, extension: [&[u8]; N]){
    let mut checked = Vec::<Box<[u8]>>::with_capacity(N);
    let mut total = 0usize;

    while let Some(ext) = path.extension() {
        if total == N {
            break;
        }

        let bytes = ext.as_bytes();
        if extension.contains(&bytes) {
            if !checked.contains(&Box::from(bytes)) {
                total += 1;
                checked.push(Box::from(bytes));
                path.set_extension("");
            } else {
                break;
            }
        }
    }
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