use saferunnet_app::{AppKernel, IdentityModule, NODE_IDENTITY_SERVICE_KEY};
use saferunnet_config::load_from_path;
use std::path::{Path, PathBuf};

const DEFAULT_KEYFILE_NAME: &str = "identity.key";

fn main() {
    saferunnet_observability::install("info").expect("install tracing");

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--check-config" {
        load_from_path(&args[2]).expect("load config");
        println!("config ok");
        return;
    }

    if args.len() == 3 && args[1] == "--bootstrap" {
        run_bootstrap(Path::new(&args[2]));
        return;
    }

    println!("saferunnet bootstrap ok");
}

fn run_bootstrap(config_path: &Path) {
    let config = load_from_path(config_path).expect("load config");
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let data_dir = resolve_data_dir(config_dir, &config.router.data_dir);
    let keyfile = resolve_keyfile_path(&data_dir, config.network.keyfile.as_deref());
    if let Some(parent) = keyfile.parent() {
        std::fs::create_dir_all(parent).expect("create identity directory");
    }

    let mut kernel = AppKernel::new();
    kernel.register(Box::new(IdentityModule::from_runtime_settings(
        config.router.nickname,
        keyfile,
    )));
    kernel.start().expect("start kernel");
    if !kernel.services().contains_key(NODE_IDENTITY_SERVICE_KEY) {
        panic!("missing identity service");
    }
    println!("identity bootstrap ok");
}

fn resolve_data_dir(config_dir: &Path, data_dir: &str) -> PathBuf {
    let data_dir = Path::new(data_dir);
    if data_dir.is_absolute() {
        data_dir.to_path_buf()
    } else {
        config_dir.join(data_dir)
    }
}

fn resolve_keyfile_path(data_dir: &Path, keyfile: Option<&str>) -> PathBuf {
    match keyfile {
        Some(keyfile) => {
            let keyfile = Path::new(keyfile);
            if keyfile.is_absolute() {
                keyfile.to_path_buf()
            } else {
                data_dir.join(keyfile)
            }
        }
        None => data_dir.join(DEFAULT_KEYFILE_NAME),
    }
}
