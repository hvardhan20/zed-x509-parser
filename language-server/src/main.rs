use std::collections::HashMap;
use std::error::Error;

use lsp_server::{Connection, ErrorCode, Message, Notification, Request, RequestId, Response};
use lsp_types::{
    ApplyWorkspaceEditParams, CodeActionOrCommand, CodeActionParams, CodeActionProviderCapability,
    CodeActionResponse, Command as LspCommand, CreateFile, CreateFileOptions,
    DocumentChangeOperation, DocumentChanges, ExecuteCommandOptions, ExecuteCommandParams, Hover,
    HoverContents, HoverProviderCapability, MarkupContent, MarkupKind, MessageType, OneOf,
    OptionalVersionedTextDocumentIdentifier, Position, Range, ResourceOp, ServerCapabilities,
    ShowMessageParams, TextDocumentEdit, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextEdit, WorkspaceEdit,
};
use x509_parser::pem::parse_x509_pem;

mod cert;

const DECODE_COMMAND: &str = "x509.decodeToFile";

const PATH_SAFE: percent_encoding::AsciiSet = percent_encoding::NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b'.')
    .remove(b'-')
    .remove(b'_')
    .remove(b'~');

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (connection, io_threads) = Connection::stdio();

    let capabilities = ServerCapabilities {
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
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
    let mut next_request_id = 1i32;

    for msg in &connection.receiver {
        match msg {
            Message::Request(req) => {
                if connection.handle_shutdown(&req)? {
                    return Ok(());
                }
                let response = match req.method.as_str() {
                    "textDocument/hover" => handle_hover(&req, &documents),
                    "textDocument/codeAction" => handle_code_action(&req, &documents),
                    "workspace/executeCommand" => handle_execute_command(
                        &req,
                        &mut documents,
                        connection,
                        &mut next_request_id,
                    ),
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
                arguments: Some(vec![serde_json::json!(uri), serde_json::json!(block.start)]),
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
    documents: &mut HashMap<String, String>,
    connection: &Connection,
    next_request_id: &mut i32,
) -> Response {
    let params = match serde_json::from_value::<ExecuteCommandParams>(req.params.clone()) {
        Ok(p) => p,
        Err(e) => return error_response(req.id.clone(), &e.to_string()),
    };

    if params.command != DECODE_COMMAND {
        return ok_null_response(req.id.clone());
    }

    match build_decoded_document(&params.arguments, documents) {
        Ok((out_uri, content)) => {
            match open_decoded_document(connection, documents, next_request_id, &out_uri, content) {
                Ok(()) => {}
                Err(message) => show_message(connection, MessageType::ERROR, &message),
            }
        }
        Err(message) => show_message(connection, MessageType::ERROR, &message),
    }

    ok_null_response(req.id.clone())
}

/// Decodes the certificate named by `args = [document uri, block offset]`
/// and returns the target file's URI and rendered content.
fn build_decoded_document(
    args: &[serde_json::Value],
    documents: &HashMap<String, String>,
) -> Result<(String, String), String> {
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
    let content = cert::render_openssl_style(&cert, block.text);

    let out_uri = decoded_document_uri(uri)?;
    Ok((out_uri, content))
}

fn decoded_document_uri(uri: &str) -> Result<String, String> {
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
    out.set_file_name(format!("{stem}.decoded.txt"));
    let out_str = out
        .to_str()
        .ok_or_else(|| "output path is not valid UTF-8".to_string())?;
    Ok(format!(
        "file://{}",
        percent_encoding::utf8_percent_encode(out_str, &PATH_SAFE)
    ))
}

/// Asks the client (via a server-initiated `workspace/applyEdit` request) to
/// create the decoded file and fill it in, which — unlike writing to disk
/// directly — makes Zed open it as a tab. Falls back to writing the file
/// straight to disk if the client rejects or doesn't support the edit.
fn open_decoded_document(
    connection: &Connection,
    documents: &mut HashMap<String, String>,
    next_request_id: &mut i32,
    out_uri: &str,
    content: String,
) -> Result<(), String> {
    let uri: lsp_types::Uri = out_uri
        .parse()
        .map_err(|_| "invalid output uri".to_string())?;

    let edit = WorkspaceEdit {
        document_changes: Some(DocumentChanges::Operations(vec![
            DocumentChangeOperation::Op(ResourceOp::Create(CreateFile {
                uri: uri.clone(),
                options: Some(CreateFileOptions {
                    overwrite: Some(true),
                    ignore_if_exists: Some(false),
                }),
                annotation_id: None,
            })),
            DocumentChangeOperation::Edit(TextDocumentEdit {
                text_document: OptionalVersionedTextDocumentIdentifier { uri, version: None },
                edits: vec![OneOf::Left(TextEdit {
                    range: Range {
                        start: Position::new(0, 0),
                        end: Position::new(u32::MAX, 0),
                    },
                    new_text: content.clone(),
                })],
            }),
        ])),
        ..Default::default()
    };

    let id = RequestId::from(*next_request_id);
    *next_request_id += 1;

    let params = serde_json::to_value(ApplyWorkspaceEditParams {
        label: Some("Decode certificate".to_string()),
        edit,
    })
    .map_err(|e| e.to_string())?;

    connection
        .sender
        .send(Message::Request(Request {
            id: id.clone(),
            method: "workspace/applyEdit".to_string(),
            params,
        }))
        .map_err(|e| e.to_string())?;

    match await_response(connection, documents, &id) {
        Ok(result) => {
            let applied = result
                .get("applied")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if applied {
                Ok(())
            } else {
                write_to_disk(out_uri, &content)
            }
        }
        Err(_) => write_to_disk(out_uri, &content),
    }
}

fn write_to_disk(out_uri: &str, content: &str) -> Result<(), String> {
    let encoded_path = out_uri
        .strip_prefix("file://")
        .ok_or_else(|| "not a local file".to_string())?;
    let path = percent_encoding::percent_decode_str(encoded_path)
        .decode_utf8()
        .map_err(|e| e.to_string())?;
    std::fs::write(path.as_ref(), content).map_err(|e| e.to_string())
}

/// Blocks until the response for `id` arrives, forwarding any notifications
/// seen in the meantime so `documents` stays in sync.
fn await_response(
    connection: &Connection,
    documents: &mut HashMap<String, String>,
    id: &RequestId,
) -> Result<serde_json::Value, String> {
    loop {
        match connection.receiver.recv() {
            Ok(Message::Response(resp)) if &resp.id == id => {
                return resp.result.ok_or_else(|| {
                    resp.error
                        .map(|e| e.message)
                        .unwrap_or_else(|| "no result".to_string())
                });
            }
            Ok(Message::Notification(not)) => handle_notification(not, documents),
            Ok(Message::Request(req)) => {
                // We don't expect nested requests from the client while
                // waiting; reply null so the client doesn't hang either.
                let _ = connection.sender.send(Message::Response(Response {
                    id: req.id,
                    result: Some(serde_json::Value::Null),
                    error: None,
                }));
            }
            Ok(Message::Response(_)) => {}
            Err(_) => return Err("connection closed".to_string()),
        }
    }
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
