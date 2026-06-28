use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

const KEY_NAMES: &[&str] = &[
    "id_rsa",
    "id_ecdsa",
    "id_ecdsa_sk",
    "id_ed25519",
    "id_ed25519_sk",
    "id_dsa",
];

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

fn ssh_dir() -> PathBuf {
    let home = env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join(".ssh")
}

fn archive_dir() -> PathBuf {
    ssh_dir().join("archive")
}

fn profile_dir(profile: &str) -> PathBuf {
    archive_dir().join(profile)
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

fn active_profile() -> Option<String> {
    let activessh = ssh_dir().join("activessh");
    fs::read_to_string(&activessh)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Find (private_key_path, pub_key_path) in `dir` using KEY_NAMES priority.
fn find_key_in_dir(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    for name in KEY_NAMES {
        let priv_path = dir.join(name);
        let pub_path = dir.join(format!("{}.pub", name));
        // Also handle underscore-pub variant (id_ed25519_pub) that some older tools write
        let pub_path_alt = dir.join(format!("{}_pub", name));
        if priv_path.exists() {
            if pub_path.exists() {
                return Some((priv_path, pub_path));
            } else if pub_path_alt.exists() {
                return Some((priv_path, pub_path_alt));
            }
        }
    }
    None
}

/// Return all id_* files in `dir` (both private and pub variants).
fn all_key_files_in_dir(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for name in KEY_NAMES {
        let priv_path = dir.join(name);
        let pub_path = dir.join(format!("{}.pub", name));
        let pub_path_alt = dir.join(format!("{}_pub", name));
        if priv_path.exists() {
            files.push(priv_path);
        }
        if pub_path.exists() {
            files.push(pub_path);
        } else if pub_path_alt.exists() {
            files.push(pub_path_alt);
        }
    }
    files
}

/// Compare the private key in `ssh_dir()` against all archived profiles.
/// Returns true if the current key's contents match some archived copy.
fn keys_are_archived(private_key: &Path, arch_dir: &Path) -> bool {
    let current_data = match fs::read(private_key) {
        Ok(d) => d,
        Err(_) => return false,
    };
    let entries = match fs::read_dir(arch_dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let prof_path = entry.path();
        if !prof_path.is_dir() {
            continue;
        }
        for name in KEY_NAMES {
            let candidate = prof_path.join(name);
            if let Ok(data) = fs::read(&candidate) {
                if data == current_data {
                    return true;
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Permission helpers
// ---------------------------------------------------------------------------

fn set_readonly(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o444));
}

fn set_private_key_perms(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

fn set_pub_key_perms(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o644));
}

// ---------------------------------------------------------------------------
// List all profile names
// ---------------------------------------------------------------------------

fn list_profiles() -> Vec<String> {
    let arch = archive_dir();
    if !arch.exists() {
        return Vec::new();
    }
    let mut profiles: Vec<String> = fs::read_dir(&arch)
        .unwrap_or_else(|_| panic!("Cannot read archive dir: {}", arch.display()))
        .flatten()
        .filter(|e| e.path().is_dir())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    profiles.sort();
    profiles
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_init(profile: &str, force: bool) {
    let prof_dir = profile_dir(profile);

    if prof_dir.exists() && !force {
        eprintln!(
            "Error: profile '{}' already exists. Use -f to overwrite.",
            profile
        );
        process::exit(1);
    }

    // Find current keys
    let ssh = ssh_dir();
    let key_pair = find_key_in_dir(&ssh);

    if key_pair.is_none() {
        eprintln!("Error: no SSH key found in {}", ssh.display());
        process::exit(1);
    }
    let (priv_key, pub_key) = key_pair.unwrap();

    // Ensure profile dir exists (clean if force)
    if prof_dir.exists() && force {
        fs::remove_dir_all(&prof_dir).expect("Failed to remove existing profile dir");
    }
    fs::create_dir_all(&prof_dir).expect("Failed to create profile directory");

    // Copy private key
    let dest_priv = prof_dir.join(priv_key.file_name().unwrap());
    fs::copy(&priv_key, &dest_priv).expect("Failed to copy private key");
    set_readonly(&dest_priv);

    // Copy pub key
    let dest_pub = prof_dir.join(pub_key.file_name().unwrap());
    fs::copy(&pub_key, &dest_pub).expect("Failed to copy public key");
    set_readonly(&dest_pub);

    // Write activessh marker inside the archive
    let marker = prof_dir.join("activessh");
    fs::write(&marker, profile).expect("Failed to write activessh marker");

    println!("Profile '{}' created at {}", profile, prof_dir.display());

    // Activate
    cmd_activate(profile);
}

fn cmd_activate(profile: &str) {
    let prof_dir = profile_dir(profile);

    if !prof_dir.exists() {
        eprintln!("Error: profile '{}' does not exist.", profile);
        process::exit(1);
    }

    let ssh = ssh_dir();
    let key_pair = find_key_in_dir(&prof_dir);

    if key_pair.is_none() {
        eprintln!(
            "Error: no key files found in profile '{}'.",
            profile
        );
        process::exit(1);
    }
    let (priv_key, pub_key) = key_pair.unwrap();

    // Copy private key to ~/.ssh/
    // Make writable first — fs::copy on macOS (copyfile) propagates source
    // permissions (0o444 from the archive), so an existing dest may be read-only.
    let dest_priv = ssh.join(priv_key.file_name().unwrap());
    if dest_priv.exists() {
        let _ = fs::set_permissions(&dest_priv, fs::Permissions::from_mode(0o600));
    }
    fs::copy(&priv_key, &dest_priv).expect("Failed to copy private key");
    set_private_key_perms(&dest_priv);

    // Copy public key to ~/.ssh/
    let dest_pub = ssh.join(pub_key.file_name().unwrap());
    if dest_pub.exists() {
        let _ = fs::set_permissions(&dest_pub, fs::Permissions::from_mode(0o644));
    }
    fs::copy(&pub_key, &dest_pub).expect("Failed to copy public key");
    set_pub_key_perms(&dest_pub);

    // Write ~/.ssh/activessh
    let activessh = ssh.join("activessh");
    fs::write(&activessh, profile).expect("Failed to write activessh");

    println!("Activated profile '{}'.", profile);
}

fn cmd_list() {
    let profiles = list_profiles();
    if profiles.is_empty() {
        println!("No profiles found. Use 'sshenv init <profile>' to create one.");
        return;
    }
    let active = active_profile();
    for p in &profiles {
        if active.as_deref() == Some(p.as_str()) {
            println!("* {}", p);
        } else {
            println!("  {}", p);
        }
    }
}

fn cmd_switch() {
    let profiles = list_profiles();
    if profiles.is_empty() {
        eprintln!("Error: no profiles found.");
        process::exit(1);
    }

    let active = active_profile();
    let next = if let Some(current) = active {
        let idx = profiles.iter().position(|p| p == &current);
        match idx {
            Some(i) => profiles[(i + 1) % profiles.len()].clone(),
            None => profiles[0].clone(),
        }
    } else {
        profiles[0].clone()
    };

    println!("Switching to profile '{}'...", next);
    cmd_activate(&next);
}

fn cmd_delete(profile: &str, force: bool) {
    if !force {
        eprintln!("Error: 'sshenv delete' requires -f flag.");
        process::exit(1);
    }

    let prof_dir = profile_dir(profile);
    if !prof_dir.exists() {
        eprintln!("Error: profile '{}' does not exist.", profile);
        process::exit(1);
    }

    fs::remove_dir_all(&prof_dir).expect("Failed to remove profile directory");
    println!("Profile '{}' deleted.", profile);

    // If we just deleted the active profile, clear activessh
    if active_profile().as_deref() == Some(profile) {
        let activessh = ssh_dir().join("activessh");
        let _ = fs::remove_file(&activessh);
    }
}

fn cmd_new() {
    let mut stdout = io::stdout();

    // 1. Profile name — first, so the key goes straight into the archive
    print!("Profile name: ");
    stdout.flush().unwrap();
    let mut profile_input = String::new();
    io::stdin().read_line(&mut profile_input).unwrap();
    let profile = profile_input.trim().to_string();
    if profile.is_empty() {
        eprintln!("Error: profile name cannot be empty.");
        process::exit(1);
    }

    let prof_dir = profile_dir(&profile);
    if prof_dir.exists() {
        eprintln!("Error: profile '{}' already exists. Choose a different name or delete it first.", profile);
        process::exit(1);
    }

    // 2. Key type
    print!("Key type [rsa/ed25519] (default: ed25519): ");
    stdout.flush().unwrap();
    let mut key_type_input = String::new();
    io::stdin().read_line(&mut key_type_input).unwrap();
    let key_type = if key_type_input.trim().to_lowercase() == "rsa" { "rsa" } else { "ed25519" };

    // 3. Comment (optional)
    print!("Comment (optional, e.g. user@host): ");
    stdout.flush().unwrap();
    let mut comment = String::new();
    io::stdin().read_line(&mut comment).unwrap();
    let comment = comment.trim().to_string();

    // Create profile directory and generate key directly into it
    fs::create_dir_all(&prof_dir).expect("Failed to create profile directory");

    let key_name = if key_type == "rsa" { "id_rsa" } else { "id_ed25519" };
    let key_path = prof_dir.join(key_name);
    let pub_key_path = prof_dir.join(format!("{}.pub", key_name));

    let mut keygen_args = vec![
        "-t".to_string(),
        key_type.to_string(),
        "-f".to_string(),
        key_path.to_string_lossy().to_string(),
    ];
    if !comment.is_empty() {
        keygen_args.push("-C".to_string());
        keygen_args.push(comment);
    }

    println!("Generating {} key for profile '{}'...", key_type, profile);
    let status = Command::new("ssh-keygen")
        .args(&keygen_args)
        .status()
        .expect("Failed to run ssh-keygen");

    if !status.success() {
        eprintln!("Error: ssh-keygen failed.");
        let _ = fs::remove_dir_all(&prof_dir);
        process::exit(1);
    }

    // Archive permissions — read-only in the store
    set_readonly(&key_path);
    if pub_key_path.exists() {
        set_readonly(&pub_key_path);
    }

    // Write activessh marker inside the archive
    let marker = prof_dir.join("activessh");
    fs::write(&marker, &profile).expect("Failed to write activessh marker");

    println!();
    println!("Profile '{}' created at {}.", profile, prof_dir.display());
    println!("Key is NOT active. Run 'sshenv activate {}' to use it.", profile);
}

fn cmd_clear(force: bool) {
    let ssh = ssh_dir();
    let key_files = all_key_files_in_dir(&ssh);

    if key_files.is_empty() {
        println!("No SSH keys found in ~/.ssh/. Nothing to clear.");
        return;
    }

    // Safety: check if private key is archived
    if !force {
        let arch = archive_dir();
        for f in &key_files {
            // Only check private keys (not .pub)
            let name = f.file_name().unwrap().to_string_lossy();
            if name.ends_with(".pub") || name.ends_with("_pub") {
                continue;
            }
            if !keys_are_archived(f, &arch) {
                eprintln!(
                    "Error: key '{}' is not archived in any profile. Use -f to force removal.",
                    f.display()
                );
                process::exit(1);
            }
        }
    }

    for f in &key_files {
        // Make writable first in case it was set read-only
        let _ = fs::set_permissions(f, fs::Permissions::from_mode(0o644));
        fs::remove_file(f).unwrap_or_else(|e| {
            eprintln!("Warning: could not remove {}: {}", f.display(), e);
        });
    }

    // Clear activessh
    let activessh = ssh.join("activessh");
    let _ = fs::remove_file(&activessh);

    println!("Cleared current SSH keys.");
}

fn cmd_locate() {
    let ssh = ssh_dir();
    match find_key_in_dir(&ssh) {
        Some((priv_key, _)) => {
            println!("{}", priv_key.display());
        }
        None => {
            println!("No SSH key found in {}", ssh.display());
            process::exit(1);
        }
    }
}

fn cmd_copy(profile: Option<&str>) {
    let pub_key_path = if let Some(p) = profile {
        // Use archived profile's pub key
        let prof_dir = profile_dir(p);
        if !prof_dir.exists() {
            eprintln!("Error: profile '{}' does not exist.", p);
            process::exit(1);
        }
        match find_key_in_dir(&prof_dir) {
            Some((_, pub_key)) => pub_key,
            None => {
                eprintln!("Error: no key found in profile '{}'.", p);
                process::exit(1);
            }
        }
    } else {
        // Use current ~/.ssh/ pub key
        match find_key_in_dir(&ssh_dir()) {
            Some((_, pub_key)) => pub_key,
            None => {
                eprintln!("Error: no SSH key found in ~/.ssh/");
                process::exit(1);
            }
        }
    };

    let contents = fs::read_to_string(&pub_key_path).expect("Failed to read public key");

    // Detect clipboard command
    let os = std::env::consts::OS;
    let copied = if os == "macos" || cfg!(target_os = "macos") {
        // macOS
        let mut child = Command::new("pbcopy")
            .stdin(process::Stdio::piped())
            .spawn()
            .expect("Failed to run pbcopy");
        child.stdin.as_mut().unwrap().write_all(contents.as_bytes()).unwrap();
        child.wait().map(|s| s.success()).unwrap_or(false)
    } else {
        // Linux: try xclip, then xsel
        let result = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(process::Stdio::piped())
            .spawn();
        match result {
            Ok(mut child) => {
                child.stdin.as_mut().unwrap().write_all(contents.as_bytes()).unwrap();
                child.wait().map(|s| s.success()).unwrap_or(false)
            }
            Err(_) => {
                // try xsel
                let result2 = Command::new("xsel")
                    .args(["--clipboard", "--input"])
                    .stdin(process::Stdio::piped())
                    .spawn();
                match result2 {
                    Ok(mut child) => {
                        child.stdin.as_mut().unwrap().write_all(contents.as_bytes()).unwrap();
                        child.wait().map(|s| s.success()).unwrap_or(false)
                    }
                    Err(_) => false,
                }
            }
        }
    };

    if copied {
        println!("Public key copied to clipboard: {}", pub_key_path.display());
    } else {
        eprintln!("Error: could not copy to clipboard. pbcopy/xclip/xsel not found.");
        process::exit(1);
    }
}

fn cmd_inject(host: &str, profiles: &[&str]) {
    let ssh = ssh_dir();
    let arch = archive_dir();

    // Find binary path for "self"
    let self_bin = env::current_exe().expect("Cannot determine sshenv binary path");

    for &profile in profiles {
        if profile == "self" {
            // Copy sshenv binary to remote
            println!("Injecting sshenv binary to {}...", host);

            // Create remote directory first
            let mkdir_status = Command::new("ssh")
                .args([host, "mkdir -p ~/.local/bin"])
                .status()
                .expect("Failed to run ssh mkdir");
            if !mkdir_status.success() {
                eprintln!("Warning: could not create remote ~/.local/bin, skipping.");
                continue;
            }

            let remote_path = format!("{}:~/.local/bin/sshenv", host);
            let status = Command::new("rsync")
                .args(["-avz", self_bin.to_str().unwrap(), &remote_path])
                .status()
                .expect("Failed to run rsync");
            if !status.success() {
                eprintln!("Warning: rsync for 'self' failed.");
            } else {
                // Ensure the binary is executable on the remote
                let _ = Command::new("ssh")
                    .args([host, "chmod 755 ~/.local/bin/sshenv"])
                    .status();
            }
        } else if profile == "active" {
            // Copy current ~/.ssh/id_* files
            println!("Injecting active keys to {}...", host);
            let key_pair = find_key_in_dir(&ssh);
            if key_pair.is_none() {
                eprintln!("Warning: no active key found to inject.");
                continue;
            }
            let (priv_key, pub_key) = key_pair.unwrap();
            for kf in &[priv_key, pub_key] {
                let status = Command::new("rsync")
                    .args([
                        "-avz",
                        kf.to_str().unwrap(),
                        &format!("{}:~/.ssh/", host),
                    ])
                    .status()
                    .expect("Failed to run rsync");
                if !status.success() {
                    eprintln!("Warning: rsync for active key failed.");
                }
            }
        } else {
            // Copy archived profile
            let prof_dir = arch.join(profile);
            if !prof_dir.exists() {
                eprintln!("Warning: profile '{}' does not exist, skipping.", profile);
                continue;
            }
            println!("Injecting profile '{}' to {}...", profile, host);

            // Create remote directory first — rsync won't mkdir -p parent paths
            let remote_dir = format!("~/.ssh/archive/{}", profile);
            let mkdir_status = Command::new("ssh")
                .args([host, &format!("mkdir -p {}", remote_dir)])
                .status()
                .expect("Failed to run ssh mkdir");
            if !mkdir_status.success() {
                eprintln!("Warning: could not create remote directory '{}', skipping.", remote_dir);
                continue;
            }

            // Ensure trailing slash on source so rsync copies contents into dest dir
            let src = format!("{}/", prof_dir.display());
            let dst = format!("{}:{}/", host, remote_dir);
            // Archive files are already 0o444; rsync -a preserves permissions.
            // --chmod is not supported on macOS's bundled rsync 2.x.
            let status = Command::new("rsync")
                .args(["-avz", &src, &dst])
                .status()
                .expect("Failed to run rsync");
            if !status.success() {
                eprintln!("Warning: rsync for profile '{}' failed.", profile);
            }
        }
    }
}

fn print_help() {
    println!(
        r#"sshenv - SSH key profile manager

USAGE:
    sshenv <command> [args]

COMMANDS:
    init <profile> [-f]
        Archive current ~/.ssh/id_* keys to ~/.ssh/archive/<profile>/.
        Use -f to overwrite an existing profile.
        Then activates the profile.

    activate <profile>
        Copy archived keys to ~/.ssh/ and set ~/.ssh/activessh.

    list
        List all profiles. Active profile is marked with *.

    switch
        Cycle to the next profile in alphabetical order.

    delete <profile> -f
        Delete ~/.ssh/archive/<profile>/. Requires -f.

    new
        Interactive: prompt for profile name (first), key type, and comment.
        Generates key directly into ~/.ssh/archive/<profile>/ — never
        overwrites your active ~/.ssh/id_* keys. Key is NOT activated;
        run 'sshenv activate <profile>' when ready.

    clear [-f]
        Remove current ~/.ssh/id_* files. Requires -f if keys are not archived.

    locate
        Print the path of the default SSH key in ~/.ssh/.

    copy [profile]
        Copy public key to clipboard. Uses profile's key if specified.

    inject --host <host> --profiles <p1> [p2 ...]
        rsync profiles to remote host. Special profiles: 'self' (binary), 'active'.

    help
        Show this help message."#
    );
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "init" => {
            if args.len() < 3 {
                eprintln!("Usage: sshenv init <profile> [-f]");
                process::exit(1);
            }
            let profile = &args[2];
            let force = args.iter().any(|a| a == "-f" || a == "--force");
            cmd_init(profile, force);
        }

        "activate" => {
            if args.len() < 3 {
                eprintln!("Usage: sshenv activate <profile>");
                process::exit(1);
            }
            cmd_activate(&args[2]);
        }

        "list" => {
            cmd_list();
        }

        "switch" => {
            cmd_switch();
        }

        "delete" => {
            if args.len() < 3 {
                eprintln!("Usage: sshenv delete <profile> -f");
                process::exit(1);
            }
            let profile = &args[2];
            let force = args.iter().any(|a| a == "-f" || a == "--force");
            cmd_delete(profile, force);
        }

        "new" => {
            cmd_new();
        }

        "clear" => {
            let force = args.iter().any(|a| a == "-f" || a == "--force");
            cmd_clear(force);
        }

        "locate" => {
            cmd_locate();
        }

        "copy" => {
            let profile = args.get(2).map(|s| s.as_str());
            cmd_copy(profile);
        }

        "inject" => {
            // Parse --host and --profiles
            let mut host: Option<&str> = None;
            let mut profiles: Vec<&str> = Vec::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--host" => {
                        i += 1;
                        if i < args.len() {
                            host = Some(&args[i]);
                        }
                    }
                    "--profiles" => {
                        i += 1;
                        while i < args.len() && !args[i].starts_with("--") {
                            profiles.push(&args[i]);
                            i += 1;
                        }
                        continue;
                    }
                    _ => {}
                }
                i += 1;
            }

            let host = match host {
                Some(h) => h,
                None => {
                    eprintln!("Usage: sshenv inject --host <host> --profiles <p1> [p2 ...]");
                    process::exit(1);
                }
            };

            if profiles.is_empty() {
                eprintln!("Error: no profiles specified. Use --profiles <p1> [p2 ...]");
                process::exit(1);
            }

            cmd_inject(host, &profiles);
        }

        "help" | "--help" | "-h" => {
            print_help();
        }

        "--version" | "-V" => {
            println!("sshenv {}", env!("CARGO_PKG_VERSION"));
        }

        other => {
            eprintln!("Unknown command: '{}'. Run 'sshenv help' for usage.", other);
            process::exit(1);
        }
    }
}
