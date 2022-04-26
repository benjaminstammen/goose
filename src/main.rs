use goose::file_gooser;
use std::env;

#[tokio::main]
async fn main() {
    // 40MB seems like a decent choice for chunk size?
    const DEFAULT_GOSLING_SIZE: usize = 1024 * 1024 * 40;

    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    file_gooser(file_path, DEFAULT_GOSLING_SIZE)
        .await
        .expect("Failure.");
}
