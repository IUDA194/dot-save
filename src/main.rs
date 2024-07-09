mod ssh_key;

use std::string::ToString;
use slint::SharedString;

use std::fs::File;
use std::io::Write;
use std::path::Path;

slint::include_modules!();

const PRIVATE_KEY: &str = "-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
";

fn choose_folder_func() -> String {
    // use std::path::PathBuf;
    use rfd::FileDialog;

    let path = FileDialog::new().pick_folder();
    match path {
        Some(path_buf) => path_buf.display().to_string(),
        None => "Pls enter folder to save .pass file".to_string(),
    }
}


fn main() -> Result<(), slint::PlatformError> {
    let ui = AppWindow::new()?;

    //ssh_key::generate_key_pair();

    //let inp_text = "Hi bro!".to_string();
    let encryptet_data = "SL4Mmv2boEc4TmYQW29Y8z6xOml3hkAgtRmsIEVHYbcuixPR8fq1gEes7hMguYnRQBL4p2wxptkm6OpJm/bMFdBQeXcv4zmzEaLsix3+BppIGmlW43ILQ+/139RroiwXsNKzZM6rCjOyoTF6Py7u0sc42UtBkgis6XvI0MPsX1Lxh7ywctjFs0Yr5SgYiTZea46zHgU7dqfTe7ofNPn8b940tKvZcc5EhGWqHhOx3UMW+GFKoRLA1L+xmJk7H6kTBvu2jCN1hpyNBc4PnTb1YN3sctcquwLdqUiFTzAlfTQYhyH2GROQyhyh1wXdcgGQUAgzfkUk9XGFbLwov2fnBAA0h9hRnaxLoV/xuOlZAd90bypxCamCYrfNsq4Lnqtu/6ElKRgUb/Px7Tjv9cCfLWR5qPX6NHuoF/V7rHfKWxLjhW95TLYZfUbHWZMh/RD58R93BmEU4XUT+Q9zmRVxZ2YM2WiNnXu7hb4kOnXi+mURcSc6nmZ/oFJepmpwsccygKmIlaSpT4OTUT++jwRGwS4LCBVBL9XdiJM7lY9j0f2sZlWTnfsf8uhi/zA7GtvPfc60fT0Adrjjc3Zd2rWdz48gXoR1Do5LSt+fhdnqD4V2FeKO1aspiJzuWA8GKCdJsnsX/OjtjUav091oUTFL/rKfq2QHpe97M5meAa3xboY=";
    //println!("{}", encryptet_data);
    let decrypted_data = ssh_key::decrypt_with_private_key(&PRIVATE_KEY, &encryptet_data);
    println!("{}", decrypted_data);


    ui.on_code_text({
        let ui_handle = ui.as_weak();
        move |public_key: SharedString, string: SharedString, directory: SharedString, file_name| {
            let ui: AppWindow = ui_handle.unwrap();

            let encryptet_data = ssh_key::encrypt_with_public_key(&public_key.to_string(), &string);

            println!("{}", encryptet_data);

            let directory_str: String = directory.to_string();
            let file_name_str: String = file_name.to_string();

            let path = Path::new(&directory_str).join(file_name_str).with_extension("pass");
            let mut file = match File::create(&path) {
                Err(why) => panic!("couldn't create {}: {}", path.display(), why),
                Ok(file) => file,
            };

            match file.write_all(encryptet_data.as_bytes()) {
                Err(why) => panic!("couldn't write to {}: {}", path.display(), why),
                Ok(_) => println!("successfully wrote to {}", path.display()),
            }

            ui.set_encrypted_hash(encryptet_data.into())
        }
    });

    ui.on_choose_folder({
        let ui_handle = ui.as_weak();
        move || {
            let ui: AppWindow = ui_handle.unwrap();
            let path = choose_folder_func();
            ui.set_path(path.into());
        }
    });

    ui.run()
}
