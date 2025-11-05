use std::fmt::Display;

macro_rules! parse_errors {
    ($struct_name:ident is $(
        $variant:ident => $status:ident
    ),* $(,)?) => {
        #[derive(Debug, Clone)]
        pub enum $struct_name {
            $($variant(String)),*
        }

        impl $struct_name {
            pub fn to_status_code(self) -> StatusCode {
                match self {
                    $($struct_name::$variant(_) => StatusCode::$status),*
                }
            }

            pub fn inner(&self) -> &str {
                match self {
                    $($struct_name::$variant(s) => s),*
                }
            }
        }
    };
}

// request kinds
pub trait RequestKindSpec {
    fn name(&self) -> &'static str;
    fn required_headers(&self) -> &'static [HeaderKind];
}

macro_rules! request_kinds {
    ($struct_name:ident is $(
        $variant:ident = {
            name: $name:literal,
            required: [$($header:ident),* $(,)?]
        }
    ),* $(,)?) => {
        #[derive(Debug, Clone)]
        pub enum $struct_name {
            $($variant),*
        }

        impl RequestKindSpec for $struct_name {
            fn name(&self) -> &'static str {
                match self {
                    $(Self::$variant => $name),*
                }
            }

            fn required_headers(&self) -> &'static [HeaderKind] {
                use HeaderKind::*;
                match self {
                    $(Self::$variant => &[$($header),*]),*
                }
            }
        }

        impl $struct_name {
            pub fn from_str(s: &str) -> Result<Self, ParseError> {
                match s.trim().to_ascii_lowercase().as_str() {
                    $($name => Ok(Self::$variant),)*
                    other => Err(ParseError::InvalidRequestKind(other.to_string())),
                }
            }
        }
    };
}

// status codes
macro_rules! status_codes {
    ($struct_name:ident is $($name:ident = $code:literal $lexeme:literal),* $(,)?) => {

        #[derive(Clone, Debug)]
        pub enum $struct_name {
            $($name = $code),*
        }

        impl Display for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}",
                    match self {
                        $($struct_name::$name => $lexeme),*
                    })
                }
        }
        impl From<ParseError> for $struct_name {
            fn from(err: ParseError) -> Self {
                err.to_status_code()
            }
        }
    };
}
macro_rules! headers {
    ($struct_name:ident is $($name:ident = $lexeme:literal),* $(,)?) => {

        #[derive(Debug, Hash, Eq, PartialEq, PartialOrd)]
        pub enum $struct_name {
            $($name),*
        }

        impl Display for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(
                    f,
                    "{}",
                    match self {
                        $($struct_name::$name => $lexeme),*
                    })
                }
        }
        impl $struct_name {
            pub fn from_str(s: &str) -> Result<Self, ParseError> {
                match s.to_ascii_lowercase().as_str() {
                    $($lexeme => Ok(Self::$name),)*
                    other => Err(ParseError::InvalidHeaderKey(other.to_string())),
                }
            }
        }

    };
}

headers! (
    HeaderKind is
    To = "to",
    Through = "through",
    Client = "client",
    Session = "session",
    Nonce = "nonce",
    HMAC = "hmac",
    ChallengeOk = "challenge_ok",
    Hash = "hash",
    HashAccepted = "hash_accepted",
);

headers! (
    ResponseHeaderKind is
    Session = "session",
    Nonce = "nonce",
    Ok = "ok",
    SessionID = "session_id",
);

status_codes!(
    StatusCode is
    MessageSent = 1 "message sent",
    InternalError = -1 "internal error",
    BadRequest = -10 "bad request",
    InvalidRequestKind = -11 "invalid request kind",
    HeaderMissing = -20 "header missing",
    HeaderInvalid = -21 "header invalid",
    HeaderEmpty = -22 "header empty",
    AuthInvalid = -90 "auth invalid",
    Unsupported = -80 "unsupported",
    ChallengeGiven = 90 "challenge given",
    ChallengeCompleted = 91 "challenge completed",
    HashAccepted = 60 "hash accepted",
    Teapot = 0 "teapot status",
);

parse_errors! {
    ParseError is
    InvalidHeaderKey => HeaderInvalid,
    InvalidRequestKind => InvalidRequestKind,
    InvalidFormat => BadRequest,
    HeaderMissing => HeaderMissing,
    HeaderEmpty => HeaderEmpty,
}

request_kinds! {
    RequestKind is
    Send = {
        name: "send",
        required: [To, Client, Session]
    },
    ChallengePlease = {
        name: "challenge please",
        required: [Client]
    },
    ChallengeAccepted = {
        name: "challenge accepted",
        required: [Session, Client, HMAC]
    },
    Certificate = {
        name: "cert",
        required: []
    },
    HashAuth = {
        name: "hash auth",
        required: [Client, Hash]
    },
}
