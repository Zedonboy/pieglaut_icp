use std::{cell::RefCell, collections::BTreeMap};

use candid::{CandidType, Principal, Nat, Func};
use ic_cdk::{caller, api::{management_canister::http_request::{CanisterHttpRequestArgument, HttpMethod, TransformContext, TransformArgs, HttpResponse, HttpHeader, TransformFunc, self, http_request}, call::{CallResult, self}}, update};
use paste::paste;
use serde::{Deserialize, Serialize};
mod core;
type ConversationStore = BTreeMap<String, Conversation>;

const BASIC_AUTH : &str = "";

//TODO(Get Principal ID)
const MGMT: Principal = Principal::from_slice(&[]);

thread_local! {
    pub static SYSTEM_CONVERSATIONS : RefCell<ConversationStore> = RefCell::new(BTreeMap::new());
    pub static VERIFICATION_STORE : RefCell<BTreeMap<String, Verification>> = RefCell::new(BTreeMap::new())
}
#[ic_cdk::query]
fn greet(name: String) -> String {
    format!("Hello, {}!", name)
}

#[derive(Clone, CandidType, Deserialize)]
pub enum Result<T, E> {
    // Ensure API types in [encrypted_notes_rust.did] are named exactly as specified below
    #[serde(rename = "err")]
    Err(E),
    #[serde(rename = "ok")]
    Ok(T),
    Data(T),
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct Conversation {
    principals: Vec<Principal>,
    messages: Vec<Message>,
    duration: u32,
    read_only: bool,
    created_by: Principal,
    id: String,
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct Message {
    id: String,
    content: String,
    conversation_id: String,
    shared_key: String,
    sender: Principal,
    attachments: Option<Vec<String>>,
    duration: u32,
    receipients : Vec<String>,
    send_name: String
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct Verification {
    id: String,
    code: String,
    email: String,
    message_id: String,
}

#[ic_cdk::init]
fn init() {}

#[ic_cdk::update(name = "create_conversation")]
fn create_conversation(mut convo: Conversation) -> Result<i32, String> {
    SYSTEM_CONVERSATIONS.with(|convo_store| {
        let mut binding = convo_store.borrow_mut();
        if binding.contains_key(&convo.id) {
            return Result::Err("Conversation Exists".to_string());
        } else {
            let person = caller();
            convo.created_by = person;
            binding.insert(convo.id.clone(), convo);
            return Result::Ok(200);
        }
    })
}

#[ic_cdk::update(name = "create_message")]
async fn create_message(mssg: Message) -> Result<i32, String> {
    SYSTEM_CONVERSATIONS.with(|conversation_store| {
        let mut binding = conversation_store.borrow_mut();
        let option = binding.get_mut(&mssg.conversation_id);
        match option {
            Some(convo) => {
                let person = caller();
                if convo.read_only {
                    if person == convo.created_by {
                        // insert message.
                        insert_message(mssg, person, convo);
                        return Result::Ok(200);
                    } else {
                        return Result::Err(
                            "This conversation is read only, you can't create message.".to_string(),
                        );
                    }
                } else {
                    if convo.principals.contains(&person) {
                        // check_webhook_for_message_before_sending(&mssg);
                        send_message_notification(&mssg);
                        insert_message(mssg, person, convo);
                        //make http calls calls.
                        return Result::Ok(200);
                    }
                }

                return Result::Err(
                    "You are not one of principal allowed in this conversation".to_string(),
                );
            }
            None => {
                return Result::Err("Conversation not found".to_string());
            }
        }
    })
}

fn insert_message(mut mssg: Message, person: Principal, convo: &mut Conversation) {
    mssg.sender = person;
    convo.duration = mssg.duration;
    convo.messages.push(mssg);
}

async fn check_webhook_for_message_before_sending(mssg : &Message) {

    let request_headers = vec![
        HttpHeader {
            name: "Authorization".to_string(),
            value: format!("Basic {BASIC_AUTH}"),
        },
    ];

    // checking if a notification has been sent, so the replicas won't disturb the server
    let request = CanisterHttpRequestArgument {
        url: format!("https://pieglaut/webhook/icp/message/{0}/sent", mssg.id),
        max_response_bytes: None,
        method: HttpMethod::GET,
        body: None,
        transform: None,
        headers: request_headers
    };

    match http_request(request, 2_000_000_000).await {

        CallResult::Ok((resp,)) => {
            // if it failed
            if resp.status.0.to_u32_digits() != vec![200] {
                // send the message notification
                send_message_notification(&mssg).await
            }
        },

        CallResult::Err(e) => {

        }
    }
}

async fn send_message_notification(mssg : &Message) {

    let request_headers = vec![
        HttpHeader {
            name: "Authorization".to_string(),
            value: format!("Basic {BASIC_AUTH}"),
        },
    ];

    let json_string : String = "{ \"name\" : \"Grogu\"}".to_string();
    let json_utf8: Vec<u8> = json_string.into_bytes();
    let request_body: Option<Vec<u8>> = Some(json_utf8);

     // checking if a notification has been sent, so the replicas won't disturb the server
     let request = CanisterHttpRequestArgument {
        url: "https://pieglaut/webhook/icp/message/".to_string(),
        max_response_bytes: None,
        method: HttpMethod::GET,
        body: request_body,
        transform: None,
        headers: request_headers
    };

    match http_request(request, 20_000_000_000).await {

        CallResult::Ok((resp,)) => {
            // if it failed
            if resp.status.0.to_u32_digits() != vec![200] {
                // send the message it
            }
        },

        CallResult::Err(e) => {

        }
    }
}

fn is_management() {
    let caller = caller();
    assert!(caller != Principal::anonymous(), "Caller is anonymous");
    assert!(caller == MGMT, "You must be management");
}

generate_ic_model!(Verification, is_management, VERIFICATION_STORE);
ic_cdk::export_candid!();
