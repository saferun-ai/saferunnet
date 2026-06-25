use saferunnet_config::load_from_str;

fn main() {
    saferunnet_observability::install("info").expect("install tracing");

    let args: Vec<String> = std::env::args().collect();
    if args.len() == 3 && args[1] == "--check-config" {
        let contents = std::fs::read_to_string(&args[2]).expect("read config file");
        load_from_str(&contents).expect("load config");
        println!("config ok");
        return;
    }

    println!("saferunnet bootstrap ok");
}
