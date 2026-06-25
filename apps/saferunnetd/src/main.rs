use saferunnet_config::load_from_path;

fn main() {
    saferunnet_observability::install("info").expect("install tracing");

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--check-config" {
        load_from_path(&args[2]).expect("load config");
        println!("config ok");
        return;
    }

    println!("saferunnet bootstrap ok");
}
