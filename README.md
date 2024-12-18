# Sifer
Cross platform & portable directory/drive encryption utility using AES-256/128.

## Why?
Because we are at a point in time where privacy is at an all time low, and surveillance at an all time high.
Your CPU most likely has AES instructions, and that's for a reason!

## Usage
If you are building from source, download the repository, and run `cargo run --release` from within the project directory.  
If you are downloading a release build, simply run `./sifer` or double click `sifer.exe`.  

You will then be greeted by a simple interface, use the up and down arrow keys to navigate, and the enter key to select.  
You can start by customizing the settings to your liking, and then head over to Encryption -> Folder or Drive, and hack away!

Important :
Do not keep unused menus open in the UI, close them when you are done with them.

## Todo Priority
- Encrypt folder names (windows + linux)
- Fix progress bar, remove it when encryption/decryption is finished.
- Fix drive encryption/decryption, it currently doesn't do anything.
- Make registry work, simply add newly encrypted directory's path's to the registry in config.toml, and drives separately, and then display entries in the registry as a priority in directory or drive decryption.
- Add signing algorithms - (PGP? DSA? RSA? ED25519? X25519? ..........)

## Todo Non-Priority
- Compile releases and distribute