use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "unicraft",
    version = "1.0.0",
    about = "Static inspector and unpacker for Electron desktop clients"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(short, long)]
    pub audit: bool,

    #[arg(short, long, alias = "diff")]
    pub degisiklikler: bool,

    #[arg(short, long)]
    pub force: bool,

    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Archive password (falls back to 'infected' automatically)
    #[arg(short, long)]
    pub password: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Unpack an installer down to raw sources
    Extract {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Run static heuristic rules against extracted files
    Audit {
        target: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Compare two electron-builder .blockmap files
    Blockmap {
        current: PathBuf,
        #[arg(short, long)]
        previous: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Unpack, diff, and audit in a single run
    Pipeline {
        input: Option<PathBuf>,
        #[arg(short, long)]
        force: bool,
        /// Skip AST/pattern scanning stage
        #[arg(long)]
        no_audit: bool,
        /// Skip blockmap version comparison
        #[arg(long, alias = "no-diff")]
        no_degisiklikler: bool,
        #[arg(short, long)]
        password: Option<String>,
    },
}
