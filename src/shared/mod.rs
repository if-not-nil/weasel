mod meta;
mod request;
mod response;
pub use request::Request;
pub use response::Response;

meta::headers! (
    HeaderKind is
    To = "to",               // recipient of the packet, user#server
    Through = "through",     // routing through other servers
    Client = "client",       // you
    Session = "session",     // current session token
    Hash = "hash",           // used for authentication
    Timestamp = "timestamp", // unix timestamp
    Length = "length",       // body length in bytes
    Pubkey = "pubkey",       // friends
    Elaboration = "elaboration",
    Encrypted = "encrypted", // is message encrypted?
);

meta::headers! (
    ResponseHeaderKind is
    Session = "session",
    AnnouncementType = "announcement-type",
    Algo = "algo",
    Pubkey = "pubkey",
    Elaboration = "elaboration",
    MessageId = "message-id",
    Until = "until",
    Ok = "ok",
    Through = "through",     // routing through other servers
    SessionID = "session_id",
    Timestamp = "timestamp", // for message delivery or offline messages
    Count = "count",         // number of offline messages
    From = "from",           // sender of message
    Length = "length",       // body length in bytes
);

meta::status_codes!(
    StatusCode is
    // whatever
    Teapot = 0 "teapot status",

    // 1–49: general
    MessageSent = 1 "message sent",
    OfflineMessages = 5 "offline messages",

    // 50–69: authentication / certificate
    CertificateGiven = 50 "certificate given",
    HashAccepted = 60 "hash accepted",
    HashInvalid = -60 "hash not accepted",

    // negative: internal / request errors
    InternalError = -1 "internal error",
    BadRequest = -10 "bad request",
    InvalidRequestKind = -11 "invalid request kind",
    HeaderMissing = -20 "header missing",
    HeaderInvalid = -21 "header invalid",
    HeaderEmpty = -22 "header empty",
    Unsupported = -80 "unsupported",
    Denied = -99 "denied",

    // 70–79: announcements / friend system
    AnnouncementFound = 70 "announcement found",
    FriendMade = 71 "friend made",
    AnnouncementNotFound = -70 "announcement not found",
);

meta::parse_errors! {
    ParseError is
    InvalidHeaderKey => HeaderInvalid,
    InvalidRequestKind => InvalidRequestKind,
    InvalidFormat => BadRequest,
    HeaderMissing => HeaderMissing,
    HeaderEmpty => HeaderEmpty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyRequirement {
    Required,
    None,
    Optional,
}

meta::response_kinds! {
    ResponseKind is
    CertificateGiven = {
        code: CertificateGiven,
        required: [Algo, Pubkey],
        body: Required
    },
    MessageSent = {
        code: MessageSent,
        required: [Ok, Timestamp, MessageId],
        body: None
    },
    OfflineMessages = {
        code: OfflineMessages,
        required: [Count, Timestamp, From, Length],
        body: Required
    },
    HashAccepted = {
        code: HashAccepted,
        required: [Ok, SessionID, Until],
        body: None
    },
    HashInvalid = {
        code: HashInvalid,
        required: [],
        body: None
    },
    InternalError = {
        code: InternalError,
        required: [],
        body: Optional
    },
    AnnouncementFound = {
        code: AnnouncementFound,
        required: [AnnouncementType, Elaboration],
        body: Optional
    },
    AnnouncementNotFound = {
        code: AnnouncementNotFound,
        required: [],
        body: None
    },
    BadRequest = {
        code: BadRequest,
        required: [],
        body: None
    },
    HeaderMissing = {
        code: HeaderMissing,
        required: [],
        body: None
    },
    Teapot = {
        code: Teapot,
        required: [],
        body: None
    },
    FriendMade = {
        code: FriendMade,
        required: [Pubkey],
        body: None
    },

}

// request kinds and their possible responses, omitting internal errors
meta::request_kinds! {
    RequestKind is
    Certificate = {         // tofu key request
        name: "certificate",
        required: [],
        possible_responses: [CertificateGiven]
    },
    Send = {                // send message to server
        name: "send",
        required: [To, Session, Length],
        possible_responses: [MessageSent]
    },
    Sealed = {                // send message to server
        name: "sealed",
        required: [To, Encrypted, Length],
        possible_responses: [MessageSent]
    },
    HashAuth = {            // hash-based authentication
        name: "hash auth",
        required: [Client, Hash],
        possible_responses: [HashAccepted, HashInvalid]
    },
    Refresh = {             // refresh token/session
        name: "refresh",
        required: [Client, Session],
        possible_responses: [HashAccepted, HashInvalid]
    },
    Anything = {            // fetch offline messages
        name: "anything?",
        required: [Session],
        possible_responses: [OfflineMessages]
    },
    Announcement = {        // server IP/availability update
        name: "announcement",
        required: [],
        possible_responses: [AnnouncementFound, AnnouncementNotFound]
    },
    FriendRequest = {       // request friendship between servers
        name: "friend request",
        required: [],
        possible_responses: [FriendMade]
    },
    FriendMade = {          // confirm friend relationship
        name: "friend made",
        required: [Pubkey, Elaboration],
        possible_responses: [FriendMade]
    },
    Info = {                // anonymous info query
        name: "info",
        required: [],
        possible_responses: [Teapot] // could add more later
    },
    AuthInfo = {            // info query with session
        name: "auth info",
        required: [Session],
        possible_responses: [Teapot, AnnouncementFound] // friends list and info
    },
}
