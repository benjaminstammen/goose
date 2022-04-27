use clap::{Parser, Subcommand};
use goose::file_gooser;
use url::Url;

#[derive(Parser)]
#[clap(name = "goose")]
#[clap(bin_name = "goose")]
struct Goose {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[clap(arg_required_else_help = true)]
    Upload {
        /// The file that you wish to goose
        #[clap(long, parse(from_os_str))]
        file_path: std::path::PathBuf,
    },
    #[clap(arg_required_else_help = true)]
    Download {
        #[clap(long)]
        goose_url: String,
    },
}

#[tokio::main]
async fn main() {
    let args = Goose::parse();
    match args.command {
        Commands::Upload { file_path } => upload_impl(file_path).await,
        Commands::Download { goose_url } => download_impl(goose_url).await,
    }
}

async fn upload_impl(file_path: std::path::PathBuf) {
    // 40MB seems like a decent choice for chunk size?
    const DEFAULT_GOSLING_SIZE: usize = 1024 * 1024 * 40;

    //let args: Vec<String> = env::args().collect();
    //let file_path = &args[1];
    file_gooser(file_path.to_str().unwrap(), DEFAULT_GOSLING_SIZE)
        .await
        .expect("Failure.");
}

async fn download_impl(goose_url: String) {
    let url = Url::parse(goose_url.as_str()).expect("URL cannot be parsed");
    match url.scheme() {
        scheme if (scheme == "http" || scheme == "https") => println!("Workable scheme!"),
        _ => println!("Scheme is unknown - will not continue."),
    }
}
