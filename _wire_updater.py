import os
os.chdir(r"D:\Projects\RustProjects\ReburnSaferunNet")
with open(r"apps\saferunnetd\src\main.rs", "r") as f:
    content = f.read()

# Add mod updater before fn main
content = content.replace(
    "mod forwarder;\nuse forwarder::OnionForwarder;",
    "mod forwarder;\nmod updater;\nuse forwarder::OnionForwarder;"
)

# Add CLI handlers before the final println
old_final = '    println!("saferunnet bootstrap ok");'

new_final = '''    if args.len() >= 2 && args[1] == "--update-check" {
        let host = args.get(2).map(|s| s.as_str());
        match updater::check_for_updates(host) {
            Ok(status) => match status {
                updater::UpdateStatus::UpToDate { current, latest } => {
                    println!("Up to date: {current} (latest: {latest})");
                }
                updater::UpdateStatus::UpdateAvailable { current, latest, manifest } => {
                    println!("Update available: {current} -> {latest}");
                    if let Some(ref notes) = manifest.release_notes {
                        println!("Notes: {notes}");
                    }
                }
            },
            Err(e) => eprintln!("Update check failed: {e}"),
        }
        return;
    }

    if args.len() >= 2 && args[1] == "--update-apply" {
        let host = args.get(2).map(|s| s.as_str());
        println!("Checking for updates...");
        match updater::check_for_updates(host) {
            Ok(updater::UpdateStatus::UpdateAvailable { manifest, .. }) => {
                println!("Downloading update v{}...", manifest.version);
                match updater::download_update(&manifest, host) {
                    Ok(temp_path) => {
                        println!("Applying update...");
                        if let Err(e) = updater::apply_update(&temp_path) {
                            eprintln!("Failed to apply update: {e}");
                        }
                    }
                    Err(e) => eprintln!("Download failed: {e}"),
                }
            }
            Ok(updater::UpdateStatus::UpToDate { .. }) => {
                println!("Already up to date.");
            }
            Err(e) => eprintln!("Update check failed: {e}"),
        }
        return;
    }

    println!("saferunnet bootstrap ok");'''

content = content.replace(old_final, new_final)

with open(r"apps\saferunnetd\src\main.rs", "w") as f:
    f.write(content)

print("Updater wired")
