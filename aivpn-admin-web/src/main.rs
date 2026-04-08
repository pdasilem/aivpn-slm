//! AIVPN Admin Web
//!
//! Minimal management web UI that shells out to `aivpn-admin --json`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine;
use clap::Parser;
use qrcode::{render::svg, QrCode};
use rand::RngCore;
use serde_json::{Map, Value};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "AIVPN admin web UI", long_about = None)]
struct Args {
    /// Web UI bind address
    #[arg(long, default_value = "127.0.0.1:27449", env = "AIVPN_ADMIN_WEB_BIND")]
    bind: String,

    /// Path to aivpn-admin binary
    #[arg(long, default_value = "aivpn-admin", env = "AIVPN_ADMIN_BIN")]
    admin_bin: PathBuf,

    /// Path to clients database file
    #[arg(long, default_value = "/etc/aivpn/clients.json", env = "AIVPN_CLIENTS_DB")]
    clients_db: PathBuf,

    /// Path to 32-byte server private key file
    #[arg(long, env = "AIVPN_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Public server IP or host[:port] embedded into connection keys
    #[arg(long, env = "AIVPN_SERVER_IP")]
    server_ip: Option<String>,

    /// Server listen address used only to infer the port when --server-ip has no port
    #[arg(long, default_value = "0.0.0.0:443", env = "AIVPN_SERVER_LISTEN")]
    server_listen: String,

    /// Optional bearer token for API and UI access
    #[arg(long, env = "AIVPN_ADMIN_TOKEN")]
    token: Option<String>,

    /// Optional file used to load and persist the bearer token
    #[arg(long, env = "AIVPN_ADMIN_TOKEN_FILE")]
    token_file: Option<PathBuf>,

    /// Host repository path used by the Admin Web update action
    #[arg(long, default_value = "/opt/aivpn", env = "AIVPN_UPDATE_REPO_DIR")]
    update_repo_dir: PathBuf,
}

#[derive(Debug)]
struct AppState {
    args: Args,
    token: Mutex<Option<String>>,
    update_job: Arc<Mutex<UpdateJob>>,
}

#[derive(Debug, Default)]
struct UpdateJob {
    running: bool,
    finished: bool,
    success: Option<bool>,
    log: Vec<String>,
}

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[derive(Debug)]
struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

fn main() {
    let args = Args::parse();
    let bind = args.bind.clone();
    let state = Arc::new(AppState {
        token: Mutex::new(load_initial_token(&args)),
        update_job: Arc::new(Mutex::new(UpdateJob::default())),
        args,
    });
    let listener = TcpListener::bind(&bind).unwrap_or_else(|err| {
        eprintln!("failed to bind {}: {}", bind, err);
        std::process::exit(1);
    });

    eprintln!("aivpn-admin-web listening on http://{}", bind);
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            continue;
        };
        let state = state.clone();
        thread::spawn(move || {
            if let Err(err) = handle_stream(stream, &state) {
                eprintln!("request failed: {}", err);
            }
        });
    }
}

fn handle_stream(mut stream: TcpStream, state: &AppState) -> std::io::Result<()> {
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(err) => {
            write_response(
                &mut stream,
                Response::json(400, serde_json::json!({ "error": err })),
            )?;
            return Ok(());
        }
    };

    let response = route_request(&request, state);
    write_response(&mut stream, response)
}

fn route_request(request: &Request, state: &AppState) -> Response {
    if !is_authorized(request, state) {
        return Response::json(401, serde_json::json!({ "error": "unauthorized" }));
    }

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => Response::html(200, INDEX_HTML),
        ("GET", "/api/auth/status") => auth_status(state),
        ("GET", "/api/update/status") => update_status(state),
        ("POST", "/api/update/run") => run_update(state),
        ("GET", "/api/update/log") => update_log(state),
        ("POST", "/api/admin-token/generate") => generate_admin_token(state),
        ("GET", "/api/clients") => admin_json(&state.args, &["client", "list"]),
        ("POST", "/api/clients") => {
            let Ok(body) = parse_json_body(request) else {
                return Response::json(400, serde_json::json!({ "error": "invalid json body" }));
            };
            let Some(name) = body.get("name").and_then(Value::as_str) else {
                return Response::json(400, serde_json::json!({ "error": "missing name" }));
            };
            admin_json(&state.args, &["client", "add", "--name", name])
        }
        _ => route_client_operation(request, state),
    }
}

fn route_client_operation(request: &Request, state: &AppState) -> Response {
    let parts = request
        .path
        .trim_matches('/')
        .split('/')
        .collect::<Vec<_>>();

    if parts.len() == 3 && parts[0] == "api" && parts[1] == "clients" {
        let id = parts[2];
        return match request.method.as_str() {
            "GET" => admin_json(&state.args, &["client", "show", "--id", id]),
            "DELETE" => admin_json(&state.args, &["client", "remove", "--id", id]),
            _ => Response::json(404, serde_json::json!({ "error": "not found" })),
        };
    }

    if parts.len() == 4 && parts[0] == "api" && parts[1] == "clients" {
        let id = parts[2];
        return match (request.method.as_str(), parts[3]) {
            ("POST", "enable") => admin_json(&state.args, &["client", "enable", "--id", id]),
            ("POST", "disable") => admin_json(&state.args, &["client", "disable", "--id", id]),
            ("POST", "rename") => {
                let Ok(body) = parse_json_body(request) else {
                    return Response::json(400, serde_json::json!({ "error": "invalid json body" }));
                };
                let Some(name) = body.get("name").and_then(Value::as_str) else {
                    return Response::json(400, serde_json::json!({ "error": "missing name" }));
                };
                admin_json(&state.args, &["client", "rename", "--id", id, "--name", name])
            }
            _ => Response::json(404, serde_json::json!({ "error": "not found" })),
        };
    }

    Response::json(404, serde_json::json!({ "error": "not found" }))
}

fn admin_json(args: &Args, admin_args: &[&str]) -> Response {
    match run_admin(args, admin_args) {
        Ok(json) => Response::json_text(200, append_qr_svg(json)),
        Err(err) => Response::json(500, serde_json::json!({ "error": err })),
    }
}

fn append_qr_svg(json: String) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(&json) else {
        return json;
    };

    let Some(connection_key) = value
        .get("connection_key")
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        return json;
    };

    let Ok(code) = QrCode::new(connection_key.as_bytes()) else {
        return json;
    };
    let qr_svg = code
        .render::<svg::Color>()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#14202a"))
        .light_color(svg::Color("#ffffff"))
        .build();

    match &mut value {
        Value::Object(map) => {
            map.insert("connection_key_qr_svg".to_string(), Value::String(qr_svg));
        }
        _ => {
            let mut map = Map::new();
            map.insert("result".to_string(), value);
            map.insert("connection_key_qr_svg".to_string(), Value::String(qr_svg));
            value = Value::Object(map);
        }
    }

    serde_json::to_string(&value).unwrap_or(json)
}

fn run_admin(args: &Args, admin_args: &[&str]) -> Result<String, String> {
    let mut command = Command::new(&args.admin_bin);
    command
        .arg("--clients-db")
        .arg(&args.clients_db)
        .arg("--listen")
        .arg(&args.server_listen)
        .arg("--json");

    if let Some(key_file) = &args.key_file {
        command.arg("--key-file").arg(key_file);
    }
    if let Some(server_ip) = &args.server_ip {
        command.arg("--server-ip").arg(server_ip);
    }

    command.args(admin_args);
    let output = command
        .output()
        .map_err(|err| format!("failed to run {:?}: {}", args.admin_bin, err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("aivpn-admin exited with {}", output.status)
        } else {
            stderr
        });
    }

    String::from_utf8(output.stdout).map_err(|err| err.to_string())
}

fn run_capture(mut command: Command) -> Result<String, String> {
    let output = command.output().map_err(|err| err.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("command exited with {}", output.status)
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn git_capture(repo: &Path, args: &[&str]) -> Result<String, String> {
    let mut command = Command::new("git");
    command
        .arg("-c")
        .arg(format!("safe.directory={}", repo.display()))
        .arg("-C")
        .arg(repo)
        .args(args);
    run_capture(command)
}

fn update_status(state: &AppState) -> Response {
    let repo = &state.args.update_repo_dir;
    if !repo.join(".git").exists() {
        return Response::json(
            500,
            serde_json::json!({ "error": format!("git repository not found: {}", repo.display()) }),
        );
    }

    let branch = match git_capture(repo, &["rev-parse", "--abbrev-ref", "HEAD"]) {
        Ok(value) => value,
        Err(err) => return Response::json(500, serde_json::json!({ "error": err })),
    };
    let mut upstream = git_capture(repo, &["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
        .unwrap_or_else(|_| format!("origin/{}", branch));
    if upstream == "HEAD" {
        upstream = format!("origin/{}", branch);
    }
    let remote_name = upstream.split('/').next().unwrap_or("origin");
    let remote_url = git_capture(repo, &["remote", "get-url", remote_name]).unwrap_or_default();

    if let Err(err) = git_capture(repo, &["fetch", "--prune"]) {
        return Response::json(500, serde_json::json!({ "error": format!("git fetch failed: {}", err) }));
    }

    let local = match git_capture(repo, &["rev-parse", "HEAD"]) {
        Ok(value) => value,
        Err(err) => return Response::json(500, serde_json::json!({ "error": err })),
    };
    let remote = match git_capture(repo, &["rev-parse", &upstream]) {
        Ok(value) => value,
        Err(err) => return Response::json(500, serde_json::json!({ "error": err })),
    };
    let commits = if local == remote {
        Vec::new()
    } else {
        git_capture(repo, &["log", "--oneline", "--no-decorate", &format!("{}..{}", local, upstream)])
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>()
    };

    Response::json(
        200,
        serde_json::json!({
            "repo": repo,
            "branch": branch,
            "upstream": upstream,
            "remoteUrl": remote_url,
            "local": local,
            "remote": remote,
            "localShort": local.chars().take(12).collect::<String>(),
            "remoteShort": remote.chars().take(12).collect::<String>(),
            "commits": commits,
            "upToDate": local == remote
        }),
    )
}

fn run_update(state: &AppState) -> Response {
    let repo = &state.args.update_repo_dir;
    if !repo.join(".git").exists() {
        return Response::json(
            500,
            serde_json::json!({ "error": format!("git repository not found: {}", repo.display()) }),
        );
    }

    {
        let mut job = state.update_job.lock().expect("update job lock");
        if job.running {
            return Response::json(409, serde_json::json!({ "error": "update already running" }));
        }
        *job = UpdateJob {
            running: true,
            finished: false,
            success: None,
            log: vec!["Starting update...".to_string()],
        };
    }

    let repo = repo.clone();
    let job = state.update_job.clone();
    thread::spawn(move || {
        let result = run_update_job(repo, job.clone());
        let mut guard = job.lock().expect("update job lock");
        guard.running = false;
        guard.finished = true;
        guard.success = Some(result.is_ok());
        match result {
            Ok(()) => guard.log.push("Update command finished. Services may still be restarting.".to_string()),
            Err(err) => guard.log.push(format!("Update failed: {err}")),
        }
    });

    Response::json(
        202,
        serde_json::json!({ "message": "Update started", "running": true }),
    )
}

fn update_log(state: &AppState) -> Response {
    let job = state.update_job.lock().expect("update job lock");
    Response::json(
        200,
        serde_json::json!({
            "running": job.running,
            "finished": job.finished,
            "success": job.success,
            "log": job.log.join("\n")
        }),
    )
}

fn append_update_log(job: &Arc<Mutex<UpdateJob>>, line: impl Into<String>) {
    job.lock().expect("update job lock").log.push(line.into());
}

fn run_logged_command(mut command: Command, label: &str, job: Arc<Mutex<UpdateJob>>) -> Result<(), String> {
    append_update_log(&job, "");
    append_update_log(&job, format!("==> {label}"));
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    append_update_log(&job, format!("$ {:?}", command));

    let mut child = command.spawn().map_err(|err| err.to_string())?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let stdout_job = job.clone();
    let stdout_reader = stdout.map(|stream| {
        thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                append_update_log(&stdout_job, line);
            }
        })
    });

    let stderr_job = job.clone();
    let stderr_reader = stderr.map(|stream| {
        thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                append_update_log(&stderr_job, line);
            }
        })
    });

    let status = child.wait().map_err(|err| err.to_string())?;
    if let Some(reader) = stdout_reader {
        let _ = reader.join();
    }
    if let Some(reader) = stderr_reader {
        let _ = reader.join();
    }

    if status.success() {
        append_update_log(&job, format!("Command finished successfully: {label}"));
        Ok(())
    } else {
        Err(format!("{label} exited with {status}"))
    }
}

fn run_update_job(repo: PathBuf, job: Arc<Mutex<UpdateJob>>) -> Result<(), String> {
    append_update_log(
        &job,
        "Note: this job does not restart aivpn-admin-web itself, because restarting this container would cut off the live log stream. Rebuild/restart aivpn-admin-web separately after reviewing the log.",
    );

    let mut pull = Command::new("git");
    pull.arg("-c")
        .arg(format!("safe.directory={}", repo.display()))
        .arg("-C")
        .arg(&repo)
        .args(["pull", "--ff-only"]);
    run_logged_command(pull, "git pull --ff-only", job.clone())?;

    let compose_file = repo.join("docker-compose.yml");
    let services = ["aivpn-server", "prometheus", "grafana"];
    let mut compose = Command::new("docker");
    compose
        .arg("compose")
        .arg("-f")
        .arg(&compose_file)
        .arg("--project-directory")
        .arg(&repo)
        .arg("up")
        .arg("-d")
        .arg("--build")
        .args(services);

    match run_logged_command(compose, "docker compose up -d --build", job.clone()) {
        Ok(()) => {
            append_update_log(
                &job,
                "Admin UI restart is still pending. Run: docker compose up -d --build aivpn-admin-web",
            );
            Ok(())
        }
        Err(err) => {
            append_update_log(&job, format!("docker compose failed: {err}"));
            append_update_log(&job, "Trying docker-compose fallback...");
            let mut fallback = Command::new("docker-compose");
            fallback
                .arg("-f")
                .arg(&compose_file)
                .arg("--project-directory")
                .arg(&repo)
                .arg("up")
                .arg("-d")
                .arg("--build")
                .args(services);
            run_logged_command(fallback, "docker-compose up -d --build", job)
        }
    }
}

fn parse_json_body(request: &Request) -> Result<Value, serde_json::Error> {
    serde_json::from_slice(&request.body)
}

fn is_authorized(request: &Request, state: &AppState) -> bool {
    let token = state.token.lock().expect("token lock").clone();
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return true;
    };

    if let Some(value) = request.headers.get("x-aivpn-admin-token") {
        return value == &token;
    }

    request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value == token)
}

fn load_initial_token(args: &Args) -> Option<String> {
    if let Some(path) = &args.token_file {
        if let Ok(token) = std::fs::read_to_string(path) {
            let token = token.trim().to_string();
            if !token.is_empty() {
                return Some(token);
            }
        }
    }

    args.token
        .as_ref()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn generate_admin_token(state: &AppState) -> Response {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);

    if let Some(path) = &state.args.token_file {
        if let Some(parent) = path.parent() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                return Response::json(
                    500,
                    serde_json::json!({ "error": format!("failed to create token directory: {}", err) }),
                );
            }
        }
        if let Err(err) = std::fs::write(path, format!("{}\n", token)) {
            return Response::json(
                500,
                serde_json::json!({ "error": format!("failed to write token file: {}", err) }),
            );
        }
    }

    *state.token.lock().expect("token lock") = Some(token.clone());
    Response::json(
        200,
        serde_json::json!({
            "token": token,
            "restart_required": false,
            "message": "Admin token generated and applied. No restart is required."
        }),
    )
}

fn auth_status(state: &AppState) -> Response {
    let enabled = state
        .token
        .lock()
        .expect("token lock")
        .as_ref()
        .is_some_and(|token| !token.is_empty());
    Response::json(200, serde_json::json!({ "enabled": enabled }))
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;

    loop {
        let read = stream.read(&mut chunk).map_err(|err| err.to_string())?;
        if read == 0 {
            return Err("empty request".to_string());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_subslice(&buffer, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
        if buffer.len() > 64 * 1024 {
            return Err("request headers too large".to_string());
        }
    }

    let header_text = String::from_utf8_lossy(&buffer[..header_end]);
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "missing method".to_string())?
        .to_string();
    let path = request_parts
        .next()
        .ok_or_else(|| "missing path".to_string())?
        .split('?')
        .next()
        .unwrap_or("/")
        .to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }

    let content_length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);

    let mut body = buffer[header_end..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk).map_err(|err| err.to_string())?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > 1024 * 1024 {
            return Err("request body too large".to_string());
        }
    }
    body.truncate(content_length);

    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn write_response(stream: &mut TcpStream, response: Response) -> std::io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason,
        response.content_type,
        response.body.len()
    )?;
    stream.write_all(&response.body)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

impl Response {
    fn html(status: u16, body: &str) -> Self {
        Self {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.as_bytes().to_vec(),
        }
    }

    fn json(status: u16, body: Value) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            body: serde_json::to_vec(&body).unwrap_or_else(|_| b"{\"error\":\"json\"}".to_vec()),
        }
    }

    fn json_text(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            body: body.into_bytes(),
        }
    }
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AIVPN Admin</title>
  <style>
    :root {
      --bg: #101418;
      --panel: #151b22;
      --panel-2: #11171d;
      --border: #26323d;
      --border-strong: #334250;
      --text: #f3f6fa;
      --muted: #9aa8b5;
      --button: #1c2a36;
      --button-hover: #243747;
      --error: #ffb4a8;
    }
    [data-theme="light"] {
      --bg: #f4f7fa;
      --panel: #ffffff;
      --panel-2: #eef3f7;
      --border: #cad5df;
      --border-strong: #aebdca;
      --text: #14202a;
      --muted: #5f6f7e;
      --button: #e0e8ef;
      --button-hover: #cfdbe5;
      --error: #a33121;
    }
    body { margin: 0; background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; }
    main { max-width: 1080px; margin: 0 auto; padding: 24px; }
    header, section { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; margin-bottom: 16px; }
    h1, h2 { margin: 0 0 12px; }
    input, button, textarea, pre { border-radius: 8px; border: 1px solid var(--border-strong); padding: 9px 10px; background: var(--panel-2); color: var(--text); }
    button, .button-link { cursor: pointer; background: var(--button); color: var(--text); text-decoration: none; display: inline-flex; align-items: center; justify-content: center; min-height: 20px; border-radius: 8px; border: 1px solid var(--border-strong); padding: 9px 10px; }
    button:hover, .button-link:hover { background: var(--button-hover); }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--border); padding: 10px; text-align: left; vertical-align: top; }
    code, textarea, pre { width: 100%; box-sizing: border-box; word-break: break-all; }
    pre { min-height: 96px; overflow: auto; white-space: pre-wrap; }
    .row { display: flex; gap: 8px; flex-wrap: wrap; }
    .qr { display: flex; justify-content: center; align-items: center; padding: 12px; background: #fff; border-radius: 8px; margin-bottom: 12px; min-height: 64px; }
    .qr:empty { display: none; }
    .qr svg { max-width: 256px; width: 100%; height: auto; }
    .key-wrap { position: relative; display: inline-flex; flex-direction: column; align-items: center; max-width: 100%; }
    .key-popover { display: none; position: absolute; z-index: 10; top: calc(100% + 8px); left: 50%; transform: translateX(-50%); width: min(680px, calc(100vw - 48px)); background: var(--panel); color: var(--text); border: 1px solid var(--border-strong); border-radius: 8px; padding: 12px; box-shadow: 0 16px 48px rgba(0, 0, 0, .35); }
    .key-wrap.has-key.popover-open .key-popover { display: block; }
    .key-text { margin: 8px 0 0; user-select: text; }
    details { border: 1px solid var(--border); border-radius: 8px; padding: 10px; background: var(--panel-2); }
    summary { cursor: pointer; font-weight: 600; }
    dialog { background: var(--panel); color: var(--text); border: 1px solid var(--border-strong); border-radius: 8px; padding: 16px; width: min(760px, calc(100vw - 48px)); height: min(640px, 72vh); min-width: 420px; min-height: 320px; resize: both; overflow: auto; }
    dialog::backdrop { background: rgba(0, 0, 0, .45); }
    .update-dialog-body { display: flex; flex-direction: column; height: 100%; gap: 12px; }
    #updateStatus { flex: 1; min-height: 0; overflow: auto; resize: none; }
    .muted { color: var(--muted); }
    .error { color: var(--error); }
  </style>
</head>
<body>
<main>
  <header>
    <h1>AIVPN Admin</h1>
    <p class="muted">Client management through aivpn-admin CLI.</p>
    <div class="row">
      <input id="token" type="password" placeholder="Admin token">
      <button onclick="useToken()">Use token</button>
      <button onclick="generateToken()">Generate token</button>
      <button onclick="clearToken()">Clear token</button>
      <button onclick="toggleTheme()">Toggle theme</button>
      <a id="grafanaLink" class="button-link" href="/grafana" target="_blank">Grafana</a>
      <button onclick="openUpdateDialog()">Check for updates</button>
    </div>
    <div id="tokenStatus" class="muted"></div>
  </header>

  <section>
    <h2>Add client</h2>
    <div class="row">
      <input id="newName" placeholder="Client name">
      <button onclick="addClient()">Add client</button>
      <button onclick="loadClients()">Refresh clients</button>
    </div>
  </section>

  <section>
    <h2>Clients</h2>
    <div id="error" class="error"></div>
    <table>
      <thead><tr><th>Name</th><th>VPN IP</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody id="clients"></tbody>
    </table>
  </section>

  <section id="connectionSection" hidden>
    <h2>Connection key</h2>
    <div id="connectionKeyWrap" class="key-wrap" onmouseenter="showKeyPopover()" onmouseleave="scheduleHideKeyPopover()">
      <div id="connectionQr" class="qr" tabindex="0" onfocus="showKeyPopover()" onblur="scheduleHideKeyPopover()"></div>
      <div id="connectionKeyPopover" class="key-popover" role="tooltip" onmouseenter="showKeyPopover()" onmouseleave="scheduleHideKeyPopover()">
        <div class="row">
          <button onclick="copyConnectionKey()">Copy</button>
          <span id="copyStatus" class="muted"></span>
        </div>
        <pre id="connectionKeyText" class="key-text"></pre>
      </div>
    </div>
    <details id="decodedDetails">
      <summary>Decoded key</summary>
      <pre id="decodedKey"></pre>
    </details>
  </section>

  <dialog id="updateDialog">
    <div class="update-dialog-body">
      <h2>Update AIVPN</h2>
      <pre id="updateStatus">Loading...</pre>
      <div class="row">
        <button id="runUpdateButton" onclick="runUpdate()" disabled>Update now</button>
        <button id="closeUpdateButton" onclick="document.getElementById('updateDialog').close()">Cancel</button>
      </div>
    </div>
  </dialog>
</main>
<script>
const tokenInput = document.getElementById('token');
tokenInput.value = localStorage.getItem('aivpnAdminToken') || '';
document.documentElement.dataset.theme = localStorage.getItem('aivpnTheme') || 'dark';
document.getElementById('grafanaLink').href = `${location.protocol}//${location.hostname}:3000/`;
let currentConnectionKey = '';
let updatePollTimer = null;
let keyPopoverTimer = null;

function useToken() {
  localStorage.setItem('aivpnAdminToken', tokenInput.value);
  document.getElementById('tokenStatus').textContent = 'Token applied in this browser.';
  loadClients();
}

async function loadAuthStatus() {
  try {
    const data = await api('/api/auth/status', {skipAuth: true});
    if (!data.enabled) {
      tokenInput.value = '';
      localStorage.removeItem('aivpnAdminToken');
      document.getElementById('tokenStatus').textContent = 'Admin token is disabled on this server.';
    }
  } catch {
    document.getElementById('tokenStatus').textContent = 'Admin token is required.';
  }
}

async function generateToken() {
  if (tokenInput.value && !confirm('Generate a new admin token? The old token will stop working.')) return;
  try {
    const data = await api('/api/admin-token/generate', {method: 'POST'});
    tokenInput.value = data.token || '';
    localStorage.setItem('aivpnAdminToken', tokenInput.value);
    document.getElementById('tokenStatus').textContent = data.message || 'Admin token generated.';
  } catch (err) { showError(err); }
}

async function openUpdateDialog() {
  const dialog = document.getElementById('updateDialog');
  const status = document.getElementById('updateStatus');
  const button = document.getElementById('runUpdateButton');
  const closeButton = document.getElementById('closeUpdateButton');
  button.disabled = true;
  closeButton.disabled = false;
  status.textContent = 'Checking origin...';
  dialog.showModal();
  try {
    const data = await api('/api/update/status');
    const commits = data.commits && data.commits.length
      ? ['Missing commits:', ...data.commits.map(line => `  ${line}`)]
      : ['Missing commits: -'];
    status.textContent = [
      `Repository: ${data.repo}`,
      `Remote: ${data.remoteUrl || '-'}`,
      `Current: ${data.localShort}`,
      `Origin: ${data.remoteShort}`,
      data.upToDate ? 'Status: up to date' : 'Status: update available',
      '',
      ...commits
    ].join('\n');
    button.disabled = data.upToDate;
  } catch (err) {
    status.textContent = `Update check failed: ${err.message || err}`;
  }
}

async function runUpdate() {
  if (!confirm('Update from origin and restart AIVPN services? Admin UI restart is handled separately so this log can stay visible.')) return;
  const status = document.getElementById('updateStatus');
  const button = document.getElementById('runUpdateButton');
  const closeButton = document.getElementById('closeUpdateButton');
  button.disabled = true;
  closeButton.disabled = true;
  status.textContent = 'Starting update...\n';
  try {
    await api('/api/update/run', {method: 'POST'});
    pollUpdateLog();
  } catch (err) {
    status.textContent = `Update failed: ${err.message || err}`;
    closeButton.disabled = false;
  }
}

async function pollUpdateLog() {
  if (updatePollTimer) clearTimeout(updatePollTimer);
  const status = document.getElementById('updateStatus');
  const button = document.getElementById('runUpdateButton');
  const closeButton = document.getElementById('closeUpdateButton');
  try {
    const data = await api('/api/update/log');
    status.textContent = data.log || '';
    status.scrollTop = status.scrollHeight;
    if (data.running) {
      updatePollTimer = setTimeout(pollUpdateLog, 1000);
    } else {
      button.disabled = data.success !== false;
      closeButton.disabled = false;
      if (data.success === false) {
        status.textContent += '\n\nUpdate failed. You can retry after checking the log.';
      }
    }
  } catch (err) {
    status.textContent += `\n\nLog polling failed: ${err.message || err}`;
    closeButton.disabled = false;
  }
}

function clearToken() {
  tokenInput.value = '';
  localStorage.removeItem('aivpnAdminToken');
  document.getElementById('tokenStatus').textContent = 'Token cleared from this browser.';
  loadClients();
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('aivpnTheme', next);
}

async function api(path, options = {}) {
  const token = tokenInput.value || localStorage.getItem('aivpnAdminToken') || '';
  const headers = Object.assign({'Content-Type': 'application/json'}, options.headers || {});
  if (token && !options.skipAuth) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(path, Object.assign({}, options, {headers}));
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; } catch { body = {error: text}; }
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

function showError(err) {
  document.getElementById('error').textContent = err ? String(err.message || err) : '';
}

async function loadClients() {
  showError('');
  try {
    const data = await api('/api/clients');
    const rows = (data.clients || []).map(client => `
      <tr>
        <td>${escapeHtml(client.name)}<br><span class="muted">${escapeHtml(client.id)}</span></td>
        <td>${escapeHtml(client.vpn_ip)}</td>
        <td>${client.enabled ? 'enabled' : 'disabled'}</td>
        <td class="row">
          <button onclick="showClient('${client.id}')">key</button>
          <button onclick="renameClient('${client.id}', '${escapeAttr(client.name)}')">rename</button>
          <button onclick="setEnabled('${client.id}', ${!client.enabled})">${client.enabled ? 'disable' : 'enable'}</button>
          <button onclick="removeClient('${client.id}')">remove</button>
        </td>
      </tr>`).join('');
    document.getElementById('clients').innerHTML = rows;
  } catch (err) {
    showError(err);
  }
}

async function addClient() {
  const name = document.getElementById('newName').value.trim();
  if (!name) return;
  try {
    const data = await api('/api/clients', {method: 'POST', body: JSON.stringify({name})});
    document.getElementById('newName').value = '';
    setConnectionKey(data.connection_key || '', data.connection_key_qr_svg || '');
    await loadClients();
  } catch (err) { showError(err); }
}

async function showClient(id) {
  try {
    const data = await api(`/api/clients/${id}`);
    setConnectionKey(data.connection_key || '', data.connection_key_qr_svg || '');
  } catch (err) { showError(err); }
}

async function renameClient(id, currentName) {
  const name = prompt('New name', currentName);
  if (!name) return;
  try {
    await api(`/api/clients/${id}/rename`, {method: 'POST', body: JSON.stringify({name})});
    await loadClients();
  } catch (err) { showError(err); }
}

async function setEnabled(id, enabled) {
  try {
    await api(`/api/clients/${id}/${enabled ? 'enable' : 'disable'}`, {method: 'POST'});
    await loadClients();
  } catch (err) { showError(err); }
}

async function removeClient(id) {
  if (!confirm('Remove client?')) return;
  try {
    await api(`/api/clients/${id}`, {method: 'DELETE'});
    setConnectionKey('');
    await loadClients();
  } catch (err) { showError(err); }
}

function setConnectionKey(value, qrSvg = '') {
  currentConnectionKey = value || '';
  document.getElementById('connectionSection').hidden = !currentConnectionKey;
  document.getElementById('decodedDetails').open = false;
  const wrap = document.getElementById('connectionKeyWrap');
  wrap.classList.toggle('has-key', Boolean(currentConnectionKey));
  wrap.classList.remove('popover-open');
  document.getElementById('connectionQr').innerHTML = qrSvg;
  document.getElementById('connectionKeyText').textContent = currentConnectionKey;
  document.getElementById('copyStatus').textContent = '';
  document.getElementById('decodedKey').textContent = decodeConnectionKey(value);
}

function showKeyPopover() {
  if (!currentConnectionKey) return;
  if (keyPopoverTimer) {
    clearTimeout(keyPopoverTimer);
    keyPopoverTimer = null;
  }
  document.getElementById('connectionKeyWrap').classList.add('popover-open');
}

function scheduleHideKeyPopover() {
  if (keyPopoverTimer) clearTimeout(keyPopoverTimer);
  keyPopoverTimer = setTimeout(() => {
    document.getElementById('connectionKeyWrap').classList.remove('popover-open');
    keyPopoverTimer = null;
  }, 2500);
}

async function copyConnectionKey() {
  if (!currentConnectionKey) return;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(currentConnectionKey);
    } else {
      const area = document.createElement('textarea');
      area.value = currentConnectionKey;
      area.style.position = 'fixed';
      area.style.left = '-9999px';
      document.body.appendChild(area);
      area.focus();
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    document.getElementById('copyStatus').textContent = 'Copied.';
  } catch (err) {
    document.getElementById('copyStatus').textContent = `Copy failed: ${err.message || err}`;
  }
}

function decodeConnectionKey(value) {
  const prefix = 'aivpn://';
  if (!value) return '';
  let payload = value.trim();
  if (payload.startsWith(prefix)) payload = payload.slice(prefix.length);
  try {
    const padded = payload.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(payload.length / 4) * 4, '=');
    const decoded = JSON.parse(atob(padded));
    return JSON.stringify({
      server: decoded.s || null,
      serverPublicKey: decoded.k || null,
      presharedKey: decoded.p || null,
      vpnIp: decoded.i || null,
      raw: decoded
    }, null, 2);
  } catch (err) {
    return `Invalid connection key: ${err.message || err}`;
  }
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, '&#96;');
}

loadAuthStatus().finally(loadClients);
</script>
</body>
</html>
"#;
