//! `plugbox` command-line interface.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use plugbox::bench::{self, BenchOptions};
use plugbox::config::Config;
use plugbox::engine::EngineSettings;
use plugbox::{Outcome, Registry, Request, Runtime, RuntimeOptions, policy};

#[derive(Parser)]
#[command(
    name = "plugbox",
    version,
    about = "Sandboxed WebAssembly plugin runtime for edge request handlers"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the plugins in a config file (data + admin listeners).
    Serve {
        #[arg(short, long, default_value = "plugbox.toml")]
        config: PathBuf,
    },
    /// Validate a config file and compile every plugin, then exit.
    Check {
        #[arg(short, long, default_value = "plugbox.toml")]
        config: PathBuf,
    },
    /// Invoke one plugin once, without a server, and print the result.
    Run {
        #[arg(short, long, default_value = "plugbox.toml")]
        config: PathBuf,
        /// Plugin name.
        #[arg(short, long)]
        plugin: String,
        #[arg(short, long, default_value = "GET")]
        method: String,
        /// Plugin-relative path.
        #[arg(long, default_value = "/")]
        path: String,
        #[arg(short, long, default_value = "")]
        query: String,
        #[arg(short, long, default_value = "")]
        body: String,
    },
    /// Show a component's imports/exports and the import-policy verdict.
    Inspect { component: PathBuf },
    /// Benchmark cold vs pooled instantiation for one component.
    Bench {
        #[arg(long)]
        component: PathBuf,
        #[arg(long, default_value_t = 2000)]
        iterations: usize,
        /// Cold modes run iterations / cold_divisor requests.
        #[arg(long, default_value_t = 20)]
        cold_divisor: usize,
        #[arg(long, default_value_t = 4)]
        threads: usize,
        /// Plugin-relative request path.
        #[arg(long, default_value = "/")]
        path: String,
        /// Also write results as JSON.
        #[arg(long)]
        json: Option<PathBuf>,
    },
}

fn runtime_for(cfg: &Config) -> plugbox::Result<Runtime> {
    Runtime::new(RuntimeOptions {
        engine: EngineSettings {
            strategy: cfg.runtime.instance_strategy,
            pool_size: cfg.runtime.pool_size,
            max_memory: cfg.runtime.max_memory.as_usize(),
            epoch_tick: Duration::from_millis(cfg.runtime.epoch_tick_ms),
        },
        cache_dir: cfg.runtime.cache_dir.as_ref().map(|d| cfg.resolve(d)),
        outbound: Default::default(),
        max_response_body: cfg.server.max_response_body.as_usize(),
    })
}

fn serve(config: PathBuf) -> plugbox::Result<()> {
    let cfg = Config::load(&config)?;
    let runtime = Arc::new(runtime_for(&cfg)?);
    let registry = Arc::new(Registry::load(runtime, &config)?);
    let _watcher = (cfg.runtime.reload_poll_ms > 0)
        .then(|| registry.watch(Duration::from_millis(cfg.runtime.reload_poll_ms)));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(cfg.server.max_concurrency + 4)
        .build()?;
    rt.block_on(async {
        let server = plugbox::server::start(registry, &cfg.server).await?;
        println!(
            "plugbox serving on http://{} (admin: {})",
            server.data_addr,
            server
                .admin_addr
                .map(|a| format!("http://{a}"))
                .unwrap_or_else(|| "disabled".into())
        );
        let _ = tokio::signal::ctrl_c().await;
        println!("shutting down");
        server.shutdown().await;
        Ok(())
    })
}

fn check(config: PathBuf) -> plugbox::Result<()> {
    let cfg = Config::load(&config)?;
    let runtime = Arc::new(runtime_for(&cfg)?);
    let registry = Registry::load(runtime, &config)?;
    for p in registry.snapshot().plugins() {
        println!(
            "ok  {:<10} {:<12} {} ({} bytes, compiled in {:.0} ms) grants: {}",
            p.name,
            p.route,
            p.version(),
            p.compiled.size,
            p.compiled.compile_time.as_secs_f64() * 1e3,
            p.caps.summary()
        );
    }
    Ok(())
}

fn run(config: PathBuf, plugin: String, request: Request) -> plugbox::Result<()> {
    let cfg = Config::load(&config)?;
    let runtime = Arc::new(runtime_for(&cfg)?);
    let registry = Registry::load(runtime.clone(), &config)?;
    let p = registry
        .snapshot()
        .get(&plugin)
        .ok_or_else(|| plugbox::Error::ConfigInvalid(format!("no plugin named `{plugin}`")))?;
    let inv = runtime.invoke(&p, &request);
    match &inv.outcome {
        Outcome::Response(r) => {
            println!("status: {}", r.status);
            for (k, v) in &r.headers {
                println!("{k}: {v}");
            }
            println!();
            println!("{}", String::from_utf8_lossy(&r.body));
        }
        other => println!(
            "status: {} ({})\n{other:?}",
            other.http_status(),
            other.error_label().unwrap_or("")
        ),
    }
    let s = &inv.stats;
    eprintln!(
        "-- {:.2} ms total, {:.2} ms instantiate, fuel {}, peak memory {} KiB, outbound {}, denials {}",
        s.total.as_secs_f64() * 1e3,
        s.instantiate.as_secs_f64() * 1e3,
        s.fuel_consumed,
        s.memory_peak / 1024,
        s.outbound_calls,
        s.denials
    );
    Ok(())
}

fn inspect(component: PathBuf) -> plugbox::Result<bool> {
    let runtime = Runtime::new(RuntimeOptions::default())?;
    let bytes = std::fs::read(&component).map_err(|source| plugbox::Error::ComponentIo {
        path: component.clone(),
        source,
    })?;
    let c = wasmtime::component::Component::new(runtime.engine(), &bytes)
        .map_err(|e| plugbox::Error::Engine(format!("{e:#}")))?;
    let report = policy::inspect(runtime.engine(), &c);
    println!("component: {} ({} bytes)", component.display(), bytes.len());
    println!("imports:");
    for i in &report.imports {
        println!("  {i}");
    }
    println!("exports:");
    for e in &report.exports {
        println!("  {e}");
    }
    if report.is_allowed() {
        println!("policy: ALLOWED");
    } else {
        println!("policy: REJECTED");
        for v in &report.violations {
            println!("  - {v}");
        }
    }
    Ok(report.is_allowed())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("PLUGBOX_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Serve { config } => serve(config),
        Command::Check { config } => check(config),
        Command::Run {
            config,
            plugin,
            method,
            path,
            query,
            body,
        } => run(
            config,
            plugin,
            Request {
                method,
                path,
                query,
                headers: vec![],
                body: body.into_bytes(),
            },
        ),
        Command::Inspect { component } => match inspect(component) {
            Ok(true) => Ok(()),
            Ok(false) => return ExitCode::from(2),
            Err(e) => Err(e),
        },
        Command::Bench {
            component,
            iterations,
            cold_divisor,
            threads,
            path,
            json,
        } => {
            let scratch =
                std::env::temp_dir().join(format!("plugbox-bench-{}", std::process::id()));
            let opts = BenchOptions {
                component,
                iterations,
                cold_divisor,
                threads,
                scratch: scratch.clone(),
                path,
            };
            let r = bench::run(&opts).and_then(|results| {
                print!("{}", bench::render_table(&results));
                if let Some(path) = json {
                    let text = serde_json::to_string_pretty(&results).unwrap_or_default();
                    std::fs::write(path, text + "\n")?;
                }
                Ok(())
            });
            let _ = std::fs::remove_dir_all(&scratch);
            r
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
