use std::collections::HashMap;
use std::error::Error;

use lsp_server::{Connection, ErrorCode, Message, Notification, Request, RequestId, Response};
use lsp_types::{
    CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability, CodeActionResponse,
    Command as LspCommand, ExecuteCommandOptions, ExecuteCommandParams, Hover, HoverContents,
    HoverProviderCapability, MarkupContent, MarkupKind, MessageType, Position, Range,
    ServerCapabilities, ShowMessageParams, TextDocumentSyncCapability, TextDocumentSyncKind,
};
use x509_parser::pem::parse_x509_pem;

mod cert;

const DECODE_COMMAND: &str = "x509.decodeToFile";

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (connection, io_threads) = Connection::stdio();

    let capabilities = ServerCapabilities {
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        text_document_sync: Some(TextDocumentSyncCapability::Kind(
            TextDocumentSyncKind::FULL,
        )),
        code_action_provider: Some(CodeActionProviderCapability::Simple(true)),
        execute_command_provider: Some(ExecuteCommandOptions {
            commands: vec![DECODE_COMMAND.to_string()],
            ..Default::default()
        }),
        ..Default::default()
    };
    connection.initialize(serde_json::to_value(capabilities)?)?;

    run(&connection)?;
    io_threads.join()?;
    Ok(())
}

fn run(connection: &Connection) -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut documents: HashMap<String, String> = HashMap::new();

    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    return Ok(());
                }
                let response = match req.method.as_str() {
                    "textDocument/hover" => handle_hover(&req, &documents),
                    "textDocument/codeAction" => handle_code_action(&req, &documents),
                    "workspace/executeCommand" => {
                        handle_execute_command(&req, &documents, connection)
                    }
                    _ => Response {
                        id: req.id.clone(),
                        result: Some(serde_json::Value::Null),
                        error: None,
                    },
                };
                connection.sender.send(Message::Response(response))?;
            }
            Message::Notification(not) => handle_notification(not, &mut documents),
            Message::Response(_) => {}
        }
    }

    Ok(())
}

fn handle_notification(not: Notification, documents: &mut HashMap<String, String>) {
    match not.method.as_str() {
        "textDocument/didOpen" => {
            if let Ok(params) =
                serde_json::from_value::<lsp_types::DidOpenTextDocumentParams>(not.params)
            {
                documents.insert(
                    params.text_document.uri.to_string(),
                    params.text_document.text,
                );
            }
        }
        "textDocument/didChange" => {
            if let Ok(mut params) =
                serde_json::from_value::<lsp_types::DidChangeTextDocumentParams>(not.params)
            {
                // Full-document sync was negotiated, so the last change carries the whole text.
                if let Some(change) = params.content_changes.pop() {
                    documents.insert(params.text_document.uri.to_string(), change.text);
                }
            }
        }
        "textDocument/didClose" => {
            if let Ok(params) =
                serde_json::from_value::<lsp_types::DidCloseTextDocumentParams>(not.params)
            {
                documents.remove(&params.text_document.uri.to_string());
            }
        }
        _ => {}
    }
}

fn handle_hover(req: &Request, documents: &HashMap<String, String>) -> Response {
    let params = match serde_json::from_value::<lsp_types::HoverParams>(req.params.clone()) {
        Ok(p) => p,
        Err(e) => return error_response(req.id.clone(), &e.to_string()),
    };

    let uri = params
        .text_document_position_params
        .text_document
        .uri
        .to_string();
    let position = params.text_document_position_params.position;

    let hover = documents.get(&uri).and_then(|text| {
        let offset = position_to_offset(text, position);
        let block = cert::find_pem_block_at(text, offset)?;
        let markdown = describe_block(block.label, block.text)?;
        Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: markdown,
            }),
            range: Some(Range {
                start: offset_to_position(text, block.start),
                end: offset_to_position(text, block.end),
            }),
        })
    });

    ok_response(req.id.clone(), hover)
}

fn describe_block(label: &str, pem_text: &str) -> Option<String> {
    if !cert::is_certificate_label(label) {
        return None;
    }

    let (_, pem) = parse_x509_pem(pem_text.as_bytes()).ok()?;
    let cert = match pem.parse_x509() {
        Ok(cert) => cert,
        Err(e) => return Some(format!("**Failed to parse certificate**\n\n{e}")),
    };

    Some(cert::render_markdown(&cert, &pem.contents))
}

fn handle_code_action(req: &Request, documents: &HashMap<String, String>) -> Response {
    let params = match serde_json::from_value::<CodeActionParams>(req.params.clone()) {
        Ok(p) => p,
        Err(e) => return error_response(req.id.clone(), &e.to_string()),
    };

    let uri = params.text_document.uri.to_string();
    let actions: CodeActionResponse = documents
        .get(&uri)
        .and_then(|text| {
            let offset = position_to_offset(text, params.range.start);
            let block = cert::find_pem_block_at(text, offset)?;
            if !cert::is_certificate_label(block.label) {
                return None;
            }
            Some(vec![CodeActionOrCommand::Command(LspCommand {
                title: "Decode certificate to file".to_string(),
                command: DECODE_COMMAND.to_string(),
                arguments: Some(vec![
                    serde_json::json!(uri),
                    serde_json::json!(block.start),
                ]),
            })])
        })
        .unwrap_or_default();

    Response {
        id: req.id.clone(),
        result: Some(serde_json::to_value(actions).unwrap()),
        error: None,
    }
}

fn handle_execute_command(
    req: &Request,
    documents: &HashMap<String, String>,
    connection: &Connection,
) -> Response {
    let params = match serde_json::from_value::<ExecuteCommandParams>(req.params.clone()) {
        Ok(p) => p,
        Err(e) => return error_response(req.id.clone(), &e.to_string()),
    };

    if params.command != DECODE_COMMAND {
        return ok_null_response(req.id.clone());
    }

    match decode_to_file(&params.arguments, documents) {
        Ok(path) => show_message(connection, MessageType::INFO, &format!("Decoded to {path}")),
        Err(message) => show_message(connection, MessageType::ERROR, &message),
    }

    ok_null_response(req.id.clone())
}

fn decode_to_file(
    args: &[serde_json::Value],
    documents: &HashMap<String, String>,
) -> Result<String, String> {
    let uri = args
        .first()
        .and_then(|v| v.as_str())
        .ok_or("missing document uri")?;
    let start = args
        .get(1)
        .and_then(|v| v.as_u64())
        .ok_or("missing block offset")? as usize;

    let text = documents.get(uri).ok_or("document is not open")?;
    let block = cert::find_pem_block_at(text, start).ok_or("no certificate at cursor")?;
    if !cert::is_certificate_label(block.label) {
        return Err("not a certificate block".to_string());
    }

    let (_, pem) = parse_x509_pem(block.text.as_bytes()).map_err(|e| e.to_string())?;
    let cert = pem.parse_x509().map_err(|e| e.to_string())?;
    let markdown = cert::render_full_markdown(&cert, &pem.contents);

    let out_path = decoded_output_path(uri)?;
    std::fs::write(&out_path, markdown).map_err(|e| e.to_string())?;
    Ok(out_path)
}

fn decoded_output_path(uri: &str) -> Result<String, String> {
    let encoded_path = uri
        .strip_prefix("file://")
        .ok_or_else(|| "certificate is not a local file".to_string())?;
    let path_str = percent_encoding::percent_decode_str(encoded_path)
        .decode_utf8()
        .map_err(|e| e.to_string())?;
    let path = std::path::Path::new(path_str.as_ref());
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("certificate");
    let mut out = path.to_path_buf();
    out.set_file_name(format!("{stem}.decoded.md"));
    out.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "output path is not valid UTF-8".to_string())
}

fn show_message(connection: &Connection, kind: MessageType, message: &str) {
    let _ = connection.sender.send(Message::Notification(Notification {
        method: "window/showMessage".to_string(),
        params: serde_json::to_value(ShowMessageParams {
            typ: kind,
            message: message.to_string(),
        })
        .unwrap(),
    }));
}

fn position_to_offset(text: &str, position: Position) -> usize {
    let mut offset = 0usize;
    for (i, line) in text.split('\n').enumerate() {
        if i as u32 == position.line {
            return offset + position.character as usize;
        }
        offset += line.len() + 1; // account for the '\n' consumed by split
    }
    text.len()
}

fn offset_to_position(text: &str, offset: usize) -> Position {
    let prefix = &text[..offset.min(text.len())];
    let line = prefix.matches('\n').count() as u32;
    let character = match prefix.rfind('\n') {
        Some(idx) => (prefix.len() - idx - 1) as u32,
        None => prefix.len() as u32,
    };
    Position { line, character }
}

fn ok_response(id: RequestId, result: Option<Hover>) -> Response {
    Response {
        id,
        result: Some(serde_json::to_value(result).unwrap()),
        error: None,
    }
}

fn ok_null_response(id: RequestId) -> Response {
    Response {
        id,
        result: Some(serde_json::Value::Null),
        error: None,
    }
}

fn error_response(id: RequestId, message: &str) -> Response {
    Response {
        id,
        result: None,
        error: Some(lsp_server::ResponseError {
            code: ErrorCode::InternalError as i32,
            message: message.to_string(),
            data: None,
        }),
    }
}
