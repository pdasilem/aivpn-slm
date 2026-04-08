//! AIVPN Admin CLI
//!
//! Management-only binary for clients.json. It does not start the VPN gateway.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aivpn_common::crypto;
use aivpn_common::error::{Error, Result};
use aivpn_server::client_db::ClientConfig;
use aivpn_server::ClientDatabase;
use base64::Engine;
use clap::{Parser, Subcommand};
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(author, version, about = "AIVPN management CLI", long_about = None)]
struct Args {
    /// Path to clients database file
    #[arg(long, default_value = "/etc/aivpn/clients.json", global = true)]
    clients_db: PathBuf,

    /// Path to 32-byte server private key file
    #[arg(long, global = true)]
    key_file: Option<PathBuf>,

    /// Public server IP or host[:port] embedded into connection keys
    #[arg(long, env = "AIVPN_SERVER_IP", global = true)]
    server_ip: Option<String>,

    /// Server listen address used only to infer the port when --server-ip has no port
    #[arg(long, default_value = "0.0.0.0:443", global = true)]
    listen: String,

    /// Emit machine-readable JSON
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage registered clients
    Client {
        #[command(subcommand)]
        command: ClientCommand,
    },
}

#[derive(Subcommand, Debug)]
enum ClientCommand {
    /// Add a new client
    Add {
        /// Human-readable client name
        #[arg(long)]
        name: String,
    },
    /// List clients
    List,
    /// Show one client
    Show {
        /// Client ID
        #[arg(long)]
        id: String,
    },
    /// Remove a client
    Remove {
        /// Client ID
        #[arg(long)]
        id: String,
    },
    /// Rename a client
    Rename {
        /// Client ID
        #[arg(long)]
        id: String,
        /// New human-readable client name
        #[arg(long)]
        name: String,
    },
    /// Enable a client
    Enable {
        /// Client ID
        #[arg(long)]
        id: String,
    },
    /// Disable a client
    Disable {
        /// Client ID
        #[arg(long)]
        id: String,
    },
}

#[derive(Debug, Serialize)]
struct ClientView {
    id: String,
    name: String,
    vpn_ip: String,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    stats: aivpn_server::client_db::ClientStats,
}

#[derive(Debug, Serialize)]
struct ClientResponse {
    client: ClientView,
    connection_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct ClientListResponse {
    clients: Vec<ClientView>,
    total: usize,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    ok: bool,
    message: String,
    client: Option<ClientView>,
}

fn main() {
    let args = Args::parse();
    if let Err(err) = run(args) {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<()> {
    let db = ClientDatabase::load(&args.clients_db)?;

    match &args.command {
        Command::Client { command } => run_client_command(&db, command, &args),
    }
}

fn run_client_command(db: &ClientDatabase, command: &ClientCommand, args: &Args) -> Result<()> {
    match command {
        ClientCommand::Add { name } => {
            let client = db.add_client(name)?;
            let response = ClientResponse {
                connection_key: build_connection_key_for_client(&client, args)?,
                client: ClientView::from(&client),
            };
            print_client_response(&response, args.json, "created")
        }
        ClientCommand::List => {
            let clients = db.list_clients();
            let views = clients.iter().map(ClientView::from).collect::<Vec<_>>();
            let response = ClientListResponse {
                total: views.len(),
                clients: views,
            };
            if args.json {
                print_json(&response)
            } else {
                print_client_table(&response);
                Ok(())
            }
        }
        ClientCommand::Show { id } => {
            let client = db
                .find_by_id(id)
                .ok_or_else(|| Error::Session(format!("Client '{}' not found", id)))?;
            let response = ClientResponse {
                connection_key: build_connection_key_for_client(&client, args)?,
                client: ClientView::from(&client),
            };
            print_client_response(&response, args.json, "found")
        }
        ClientCommand::Remove { id } => {
            let client = db
                .find_by_id(id)
                .ok_or_else(|| Error::Session(format!("Client '{}' not found", id)))?;
            db.remove_client(id)?;
            let response = StatusResponse {
                ok: true,
                message: format!("Client '{}' removed", id),
                client: Some(ClientView::from(&client)),
            };
            print_status_response(&response, args.json)
        }
        ClientCommand::Rename { id, name } => {
            let client = db.rename_client(id, name)?;
            let response = StatusResponse {
                ok: true,
                message: format!("Client '{}' renamed", id),
                client: Some(ClientView::from(&client)),
            };
            print_status_response(&response, args.json)
        }
        ClientCommand::Enable { id } => {
            let client = db.set_client_enabled(id, true)?;
            let response = StatusResponse {
                ok: true,
                message: format!("Client '{}' enabled", id),
                client: Some(ClientView::from(&client)),
            };
            print_status_response(&response, args.json)
        }
        ClientCommand::Disable { id } => {
            let client = db.set_client_enabled(id, false)?;
            let response = StatusResponse {
                ok: true,
                message: format!("Client '{}' disabled", id),
                client: Some(ClientView::from(&client)),
            };
            print_status_response(&response, args.json)
        }
    }
}

fn build_connection_key_for_client(client: &ClientConfig, args: &Args) -> Result<Option<String>> {
    let Some(server_ip) = args.server_ip.as_deref() else {
        return Ok(None);
    };

    let Some(key_file) = args.key_file.as_deref() else {
        return Ok(None);
    };

    let server_pub = load_server_public_key(key_file)?;
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(server_pub);
    let signing_pub = load_server_signing_public_key(key_file)?;
    let signing_b64 = base64::engine::general_purpose::STANDARD.encode(signing_pub);
    let psk_b64 = base64::engine::general_purpose::STANDARD.encode(client.psk);
    let server_addr = build_connection_server_addr(&args.listen, server_ip);

    let json = serde_json::json!({
        "s": server_addr,
        "k": pub_b64,
        "g": signing_b64,
        "p": psk_b64,
        "i": client.vpn_ip.to_string(),
    });
    let json_bytes = serde_json::to_string(&json)?;
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json_bytes.as_bytes());

    Ok(Some(format!("aivpn://{}", encoded)))
}

fn load_server_public_key(key_file: &Path) -> Result<[u8; 32]> {
    let key_data = std::fs::read(key_file)?;
    if key_data.len() != 32 {
        return Err(Error::Session(format!(
            "Key file must be exactly 32 bytes, got {}",
            key_data.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);
    let kp = crypto::KeyPair::from_private_key(key);
    Ok(kp.public_key_bytes())
}

fn load_server_signing_public_key(key_file: &Path) -> Result<[u8; 32]> {
    let key_data = std::fs::read(key_file)?;
    if key_data.len() != 32 {
        return Err(Error::Session(format!(
            "Key file must be exactly 32 bytes, got {}",
            key_data.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);
    Ok(crypto::derive_server_signing_public_key(&key))
}

fn build_connection_server_addr(listen: &str, server_ip: &str) -> String {
    if server_ip.parse::<SocketAddr>().is_ok() {
        return server_ip.to_string();
    }

    let port = listen
        .parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(443);

    format!("{}:{}", server_ip, port)
}

fn print_client_response(response: &ClientResponse, json: bool, action: &str) -> Result<()> {
    if json {
        return print_json(response);
    }

    println!(
        "Client {}: {} ({})",
        action, response.client.name, response.client.id
    );
    println!("  VPN IP:  {}", response.client.vpn_ip);
    println!(
        "  Status:  {}",
        if response.client.enabled {
            "active"
        } else {
            "disabled"
        }
    );
    if let Some(connection_key) = &response.connection_key {
        println!();
        println!("Connection key:");
        println!("{}", connection_key);
    }
    Ok(())
}

fn print_status_response(response: &StatusResponse, json: bool) -> Result<()> {
    if json {
        return print_json(response);
    }

    println!("{}", response.message);
    Ok(())
}

fn print_client_table(response: &ClientListResponse) {
    if response.clients.is_empty() {
        println!("No registered clients.");
        return;
    }

    println!(
        "{:<18} {:<20} {:<12} {:<8} {:<12} {:<12} {}",
        "ID", "NAME", "VPN IP", "STATUS", "UPLOAD", "DOWNLOAD", "LAST SEEN"
    );
    println!("{}", "-".repeat(100));

    for client in &response.clients {
        let status = if client.enabled { "active" } else { "disabled" };
        let upload = format_bytes(client.stats.bytes_out);
        let download = format_bytes(client.stats.bytes_in);
        let last_seen = client
            .stats
            .last_connected
            .map(|t| t.format("%Y-%m-%d %H:%M").to_string())
            .unwrap_or_else(|| "never".to_string());

        println!(
            "{:<18} {:<20} {:<12} {:<8} {:<12} {:<12} {}",
            client.id, client.name, client.vpn_ip, status, upload, download, last_seen
        );
    }

    println!();
    println!("Total: {} client(s)", response.total);
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

impl From<&ClientConfig> for ClientView {
    fn from(client: &ClientConfig) -> Self {
        Self {
            id: client.id.clone(),
            name: client.name.clone(),
            vpn_ip: client.vpn_ip.to_string(),
            enabled: client.enabled,
            created_at: client.created_at,
            stats: client.stats.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("aivpn-admin-test-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn server_addr_keeps_explicit_port() {
        assert_eq!(
            build_connection_server_addr("0.0.0.0:443", "203.0.113.10:8443"),
            "203.0.113.10:8443"
        );
    }

    #[test]
    fn server_addr_adds_listen_port() {
        assert_eq!(
            build_connection_server_addr("0.0.0.0:9443", "203.0.113.10"),
            "203.0.113.10:9443"
        );
    }

    #[test]
    fn admin_operations_preserve_client_db_format() {
        let db_path = temp_path("clients.json");
        let db = ClientDatabase::load(&db_path).unwrap();

        let client = db.add_client("phone").unwrap();
        assert!(client.enabled);

        let renamed = db.rename_client(&client.id, "laptop").unwrap();
        assert_eq!(renamed.name, "laptop");

        let disabled = db.set_client_enabled(&client.id, false).unwrap();
        assert!(!disabled.enabled);

        let reloaded = ClientDatabase::load(&db_path).unwrap();
        let persisted = reloaded.find_by_id(&client.id).unwrap();
        assert_eq!(persisted.name, "laptop");
        assert!(!persisted.enabled);

        reloaded.remove_client(&client.id).unwrap();
        assert!(ClientDatabase::load(&db_path)
            .unwrap()
            .list_clients()
            .is_empty());
    }

    #[test]
    fn connection_key_embeds_expected_payload() {
        let db_path = temp_path("key-clients.json");
        let key_path = temp_path("server.key");
        std::fs::write(&key_path, [7u8; 32]).unwrap();

        let db = ClientDatabase::load(&db_path).unwrap();
        let client = db.add_client("phone").unwrap();
        let args = Args {
            clients_db: db_path,
            key_file: Some(key_path),
            server_ip: Some("203.0.113.10".to_string()),
            listen: "0.0.0.0:8443".to_string(),
            json: true,
            command: Command::Client {
                command: ClientCommand::List,
            },
        };

        let key = build_connection_key_for_client(&client, &args)
            .unwrap()
            .unwrap();
        let payload = key.strip_prefix("aivpn://").unwrap();
        let json_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();

        assert_eq!(json["s"], "203.0.113.10:8443");
        assert_eq!(json["i"], client.vpn_ip.to_string());
        assert!(json["k"].as_str().unwrap().len() > 10);
        assert!(json["g"].as_str().unwrap().len() > 10);
        assert!(json["p"].as_str().unwrap().len() > 10);
    }
}
