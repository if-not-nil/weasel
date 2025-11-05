use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::comms::Request;

pub struct InMemory {
    users: Arc<Mutex<HashMap<String, String>>>,
    requests: Arc<Mutex<HashMap<String, Vec<Request>>>>,
}
impl InMemory {
    pub fn new() -> Self {
        Self {
            users: Arc::new(Mutex::new(HashMap::new())),
            requests: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

enum DbError {
    UserNotFound,
}

impl SuitableDB for InMemory {
    fn store_client(&mut self, user: String, hash: String) {
        self.users.lock().unwrap().insert(user, hash);
    }

    fn check_client_auth(&self, user: &String, hash: &String) -> bool {
        if let Some(dbhash) = self.users.lock().unwrap().get(user) {
            dbhash == hash
        } else {
            false
        }
    }

    fn store_req_for_user(&self, user: String, req: Request) -> Result<(), DbError> {
        let mut map = self.requests.lock().unwrap();
        match map.get_mut(&user) {
            Some(requests) => {
                requests.push(req);
                Ok(())
            }
            None => Err(DbError::UserNotFound),
        }
    }
}
pub trait SuitableDB {
    fn store_client(&mut self, user: String, hash: String);
    fn check_client_auth(&self, user: &String, hash: &String) -> bool;
    fn store_req_for_user(&self, user: String, req: Request) -> Result<(), DbError>;
}
