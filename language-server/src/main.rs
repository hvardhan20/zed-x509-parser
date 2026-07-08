use std::collections::HashMap;
use std::error::Error;

use lsp_server::{Connection, ErrorCode, Message, Notification, Request, RequestId, Response};
use lsp_types::{
    Hover, HoverContents, HoverProviderCapability, MarkupContent, MarkupKind, Position, Range,
    ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind,
};
use x509_parser::pem::parse_x509_pem;

mod cert;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let (connection, io_threads) = Connection::stdio();

    let capabilities = ServerCapabilities {
        hover_provider: Some(HoverProviderCapability::Simple(true)),
        text_document_sync: Some(TextDocumentSyncCapability::Kind(
            TextDocumentSyncKind::FULL,
        )),
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
                if req.method == "textDocument/hover" {
                    let response = handle_hover(&req, &documents);
                    connection.sender.send(Message::Response(response))?;
                }
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
    if !matches!(
        label,
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE"
    ) {
        return None;
    }

    let (_, pem) = parse_x509_pem(pem_text.as_bytes()).ok()?;
    let cert = match pem.parse_x509() {
        Ok(cert) => cert,
        Err(e) => return Some(format!("**Failed to parse certificate**\n\n{e}")),
    };

    Some(cert::render_markdown(&cert, &pem.contents))
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
