use std::{collections::HashMap, fmt::Display};

use crate::{encryption, meta::*};

/// ===== request =====
#[derive(Debug)]
pub struct Request {
    pub version: String,
    pub kind: RequestKind,
    pub headers: HashMap<HeaderKind, String>,
    pub body: Option<String>,
}

impl TryFrom<String> for Request {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, ParseError> {
        let mut lines = value.lines();

        // headline
        let first_line = lines
            .next()
            .ok_or_else(|| ParseError::InvalidFormat("missing request kind".to_string()))?;

        let kind = RequestKind::from_str(first_line)?;

        // headers
        let mut headers = HashMap::new();
        for line in &mut lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }

            // expect "key: value"
            let (key, value) = trimmed.split_once(':').ok_or_else(|| {
                ParseError::InvalidFormat(format!("\"{trimmed}\" is not a valid header line. headers must be formatted as [name]: [value]"))
            })?;

            let key_kind = HeaderKind::from_str(key)?;
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err(ParseError::HeaderEmpty(format!("header empty: {key}")));
            };

            headers.insert(key_kind, value.trim().to_string());
        }
        for required in kind.required_headers() {
            if !headers.contains_key(&required) {
                return Err(ParseError::HeaderMissing(format!("{required:?}")));
            }
        }

        // body
        let body_text: String = lines.collect::<Vec<_>>().join("\n").trim().to_string();
        let body = if !body_text.is_empty() {
            Some(body_text)
        } else {
            None
        };

        Ok(Request {
            kind,
            headers,
            body: body,
            version: "v0.1".to_string(),
        })
    }
}

/// ===== response =====
#[derive(Debug)]
pub struct Response {
    status: StatusCode,
    headers: HashMap<ResponseHeaderKind, String>,
    body: Option<String>,
}

impl Response {
    pub fn new(status: StatusCode) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: None,
        }
    }
    pub fn with_body(status: StatusCode, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: HashMap::new(),
            body: Some(body.into()),
        }
    }
    pub fn header(mut self, kind: ResponseHeaderKind, value: String) -> Self {
        self.headers.insert(kind, value);
        self
    }
}

impl Into<Vec<u8>> for Response {
    fn into(self) -> Vec<u8> {
        self.to_string().as_bytes().into()
    }
}

impl Display for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "v{} status {}: {}{}\n",
            crate::VERSION,
            self.status.clone() as i32,
            self.status.to_string(),
            match &self.body {
                Some(body) => {
                    format!("\n\n{}", body)
                }
                None => String::new(),
            }
        )
    }
}

pub fn sample_request() {
    // ingredients:
    let psk = "very secret key between client and server";
    let client_id = { || "jebediah".to_string() };
    // client: pls
    let mut req1 = Request {
        kind: RequestKind::from_str("challenge please").unwrap(),
        headers: HashMap::new(),
        body: None,
        version: "v0.1".to_string(),
    };
    req1.headers.insert(HeaderKind::Client, client_id());
    println!("-> client: {:#?}", req1);

    // server: sure
    let mut res1 = Response::new(StatusCode::ChallengeGiven);
    let nonce_b64 = encryption::gen_nonce();
    let session_id = encryption::gen_token(16);
    res1.headers.insert(HeaderKind::Nonce, nonce_b64.clone());
    res1.headers.insert(HeaderKind::Session, session_id.clone());
    println!("<- server: {:#?}", res1);

    // client: bet
    let client_hmac = encryption::compute_hmac(psk.as_bytes(), &nonce_b64, "jebediah");
    let mut req2 = Request {
        kind: RequestKind::from_str("challenge accepted").unwrap(),
        headers: HashMap::new(),
        body: None,
        version: "v0.1".to_string(),
    };
    req2.headers.insert(HeaderKind::Client, client_id());
    req2.headers.insert(HeaderKind::Session, session_id.clone());
    req2.headers.insert(HeaderKind::HMAC, client_hmac.clone());
    println!("-> client: {:#?}", req2);

    // server: *checks*
    let expected_hmac = encryption::compute_hmac(psk.as_bytes(), &nonce_b64, "jebediah");
    let mut res2 = Response::new(StatusCode::ChallengeCompleted);
    res2.headers.insert(HeaderKind::Session, session_id);
    res2.headers.insert(
        HeaderKind::ChallengeOk,
        (client_hmac == expected_hmac).to_string(),
    );
    println!("<- server: {:#?}", res2);
}
