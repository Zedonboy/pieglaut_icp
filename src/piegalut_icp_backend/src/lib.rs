use std::{cell::RefCell, collections::BTreeMap, str::FromStr};

use candid::{CandidType, Nat, Principal};
use ic_cdk::{
    api::{
        call::CallResult,
        management_canister::http_request::{http_request, CanisterHttpRequestArgument, HttpHeader, HttpMethod},
    },
    caller, update, query,
};
use paste::paste;
use serde::{Deserialize, Serialize};
use serde_json::json;
use types::{
    CanisterId, VetKDCurve, VetKDEncryptedKeyReply, VetKDEncryptedKeyRequest, VetKDKeyId,
    VetKDPublicKeyReply, VetKDPublicKeyRequest,
};

mod types;

const VETKD_SYSTEM_API_CANISTER_ID: &str = "s55qq-oqaaa-aaaaa-aaakq-cai";

mod core;
type ConversationStore = BTreeMap<String, Conversation>;

const BASIC_AUTH: &str = "";

//TODO(Get Principal ID)
const MGMT: Principal = Principal::from_slice(&[]);

thread_local! {
    static SYSTEM_CONVERSATIONS : RefCell<ConversationStore> = RefCell::new(BTreeMap::new());
    static VERIFICATION_STORE : RefCell<BTreeMap<String, Verification>> = RefCell::new(BTreeMap::new());
    static GENERAL_KEY_STORE : RefCell<BTreeMap<String, String>> = RefCell::new(BTreeMap::new());
    static TWOFA_STORE : RefCell<BTreeMap<String, TWOFA>> = RefCell::new(BTreeMap::new());
    static MESSAGE_STORE : RefCell<BTreeMap<String, Message>> = RefCell::new(BTreeMap::new());
    static PROFILE_STORE : RefCell<BTreeMap<String, Profile>> = RefCell::new(BTreeMap::new());
    static EMAIL_BLOCK_STORE : RefCell<BTreeMap<String, Vec<Principal>>> = RefCell::new(BTreeMap::new())
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
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct Conversation {
    receipients: Vec<String>,
    messages: Vec<String>,
    duration: u32,
    read_only: bool,
    created_by: Principal,
    id: String,
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct Profile {
    name : String,
    email : String
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct Message {
    id: String,
    content: String,
    conversation_id: String,
    sender: Principal,
    attachments: Option<Vec<String>>,
    duration: u32,
    // this means Email.
    receipient_id: String,
    // this is Principal ID
    receiver: String
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct Verification {
    id: String,
    code: String,
    email: String,
    message_id: String,
}

#[derive(Clone, CandidType, Serialize, Deserialize)]
struct TWOFA {
    id: String,
    code: String,
    expire_at: u64,
    receipient_id: String
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

#[ic_cdk::update(name = "send_message")]
async fn send_message(mssg: Message) -> Result<i32, String> {
    let optional_mssg = MESSAGE_STORE.with(|store|{
        let binding = store.borrow();
        return binding.contains_key(&mssg.id);
    });

    if optional_mssg {
        return Result::Err("Message Exists".to_string());
    }

    SYSTEM_CONVERSATIONS.with(|conversation_store| {
        let mut binding = conversation_store.borrow_mut();
        let option = binding.get_mut(&mssg.conversation_id);
        match option {
            Some(convo) => {
                let person = caller();
                let optional_profile = PROFILE_STORE.with(|profile_store|{
                    let binding = profile_store.borrow();
                    let x = binding.get(&person.to_string());
                    x.cloned()
                });

                if optional_profile.is_none() {
                    return Result::Err("You are not registered into our system".to_string());
                }

                if convo.read_only {
                    if person == convo.created_by {
                        // insert message.
                        let cloned_mssg = mssg.clone();
                        let cloned_profile = optional_profile.unwrap().clone();
                        ic_cdk::spawn(send_message_notification(cloned_mssg, cloned_profile));
                        insert_message(mssg, person, convo);
                        return Result::Ok(200);
                    } else {
                        return Result::Err(
                            "This conversation is read only, you can't create message.".to_string(),
                        );
                    }
                } else {
                   
                    if convo.receipients.contains(&optional_profile.as_ref().unwrap().email) {
                        // check_webhook_for_message_before_sending(&mssg);
                        let cloned_mssg = mssg.clone();
                        let cloned_profile = optional_profile.unwrap().clone();
                        ic_cdk::spawn(send_message_notification(cloned_mssg, cloned_profile));
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
    convo.messages.push(mssg.id.clone());
    MESSAGE_STORE.with(|store| {
        store.borrow_mut().insert(mssg.id.clone(), mssg)
    });
}


async fn send_message_notification(mssg: Message, profile : Profile) {
   
    let request_headers = vec![HttpHeader {
        name: "Authorization".to_string(),
        value: format!("Basic {BASIC_AUTH}"),
    }];

    let request_data = json!({
        "id" : mssg.id,
        "receipient_id": mssg.receipient_id,
        "sender_name": profile.name,
        "sender_email" : profile.email
    });

    let json_utf8: Vec<u8> = request_data.to_string().into_bytes();
    let request_body: Option<Vec<u8>> = Some(json_utf8);

    // checking if a notification has been sent, so the replicas won't disturb the server
    let request = CanisterHttpRequestArgument {
        url: "https://pieglaut/webhook/icp/message/".to_string(),
        max_response_bytes: None,
        method: HttpMethod::POST,
        body: request_body,
        transform: None,
        headers: request_headers,
    };

    match http_request(request, 20_000_000_000).await {
        CallResult::Ok((resp,)) => {
            // if it failed
            if resp.status == Nat::from(200u32) {
                // send the message it
            }
        }

        CallResult::Err(e) => {}
    }
}

// THis function fetches an entity based on Indexed parameter, which in our case its "code" param.
// This approach aids in faster search.
#[update]
async fn get_verification_by_parameter(param_value: String) -> Result<Verification, String> {
    is_management();
    GENERAL_KEY_STORE.with(|store| {
        let binding = store.borrow();
        let entity_id = binding.get(&param_value);
        match entity_id {
            Some(id) => {
                VERIFICATION_STORE.with(|v_store| {
                    let binding = v_store.borrow();
                    let verification_option = binding.get(id);
                    if verification_option.is_some() {
                        return Result::Ok(verification_option.unwrap().clone())
                    } else {
                        return  Result::Err("Verification entity not found".to_string());
                    }
                })
            }
            None => {
                return  Result::Err("Parameter not found".to_string());
            }
        }
    })
}

#[update]
async fn get_twofa_by_parameter(param_value: String) -> Result<TWOFA, String> {
    is_management();
    GENERAL_KEY_STORE.with(|store| {
        let binding = store.borrow();
        let entity_id = binding.get(&param_value);
        match entity_id {
            Some(id) => {
                TWOFA_STORE.with(|v_store| {
                    let binding = v_store.borrow();
                    let twofa_option = binding.get(id);
                    if twofa_option.is_some() {
                        return Result::Ok(twofa_option.unwrap().clone())
                    } else {
                        return  Result::Err("Twofa entity not found".to_string());
                    }
                })
            }
            None => {
                return  Result::Err("Parameter not found".to_string());
            }
        }
    })
}

#[update]
async fn symmetric_key_verification_key() -> String {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![b"symmetric_key".to_vec()],
        key_id: bls12_381_test_key_1(),
    };

    let (response,): (VetKDPublicKeyReply,) = ic_cdk::api::call::call(
        vetkd_system_api_canister_id(),
        "vetkd_public_key",
        (request,),
    )
    .await
    .expect("call to vetkd_public_key failed");

    hex::encode(response.public_key)
}

#[update]
async fn encrypted_symmetric_key_for_caller(encryption_public_key: Vec<u8>) -> String {
    debug_println_caller("encrypted_symmetric_key_for_caller");

    let request = VetKDEncryptedKeyRequest {
        derivation_id: ic_cdk::caller().as_slice().to_vec(),
        public_key_derivation_path: vec![b"symmetric_key".to_vec()],
        key_id: bls12_381_test_key_1(),
        encryption_public_key,
    };

    let (response,): (VetKDEncryptedKeyReply,) = ic_cdk::api::call::call(
        vetkd_system_api_canister_id(),
        "vetkd_encrypted_key",
        (request,),
    )
    .await
    .expect("call to vetkd_encrypted_key failed");

    hex::encode(response.encrypted_key)
}

#[update]
async fn ibe_encryption_key() -> String {
    let request = VetKDPublicKeyRequest {
        canister_id: None,
        derivation_path: vec![b"ibe_encryption".to_vec()],
        key_id: bls12_381_test_key_1(),
    };

    let (response,): (VetKDPublicKeyReply,) = ic_cdk::api::call::call(
        vetkd_system_api_canister_id(),
        "vetkd_public_key",
        (request,),
    )
    .await
    .expect("call to vetkd_public_key failed");

    hex::encode(response.public_key)
}

#[update]
async fn encrypted_ibe_decryption_key_for_caller(encryption_public_key: Vec<u8>) -> String {
    debug_println_caller("encrypted_ibe_decryption_key_for_caller");

    let request = VetKDEncryptedKeyRequest {
        derivation_id: ic_cdk::caller().as_slice().to_vec(),
        public_key_derivation_path: vec![b"ibe_encryption".to_vec()],
        key_id: bls12_381_test_key_1(),
        encryption_public_key,
    };

    let (response,): (VetKDEncryptedKeyReply,) = ic_cdk::api::call::call(
        vetkd_system_api_canister_id(),
        "vetkd_encrypted_key",
        (request,),
    )
    .await
    .expect("call to vetkd_encrypted_key failed");

    hex::encode(response.encrypted_key)
}


#[query]
async fn public_get_profile() -> Profile {
    let person = caller();
    assert!(person != Principal::anonymous(), "Anonymous call not allowed");
    let optional_profile = PROFILE_STORE.with(|store| {
        let binding = store.borrow();
        binding.get(&person.to_string()).cloned()
    });

    assert!(optional_profile.is_some(), "You must be registered");
    optional_profile.unwrap()
}

#[update]
async fn public_create_profile(twofa_code : String, profile : Profile) -> Result<u32, ()> {
    let optional_twofa = TWOFA_STORE.with(|store|
    {
        let binding = store.borrow();
        binding.get(&twofa_code).cloned()
    });

    assert!(optional_twofa.is_some(), "2FA has expired");
    let person = caller();
    assert!(person != Principal::anonymous());
    assert!(&optional_twofa.unwrap().receipient_id == &profile.email, "Email must match with the 2FA code");

    return  PROFILE_STORE.with(|store| {
        let mut binding = store.borrow_mut();
        binding.insert(person.to_string(), profile);
        return  Result::Ok(200);
    })
}

#[update]
async fn public_update_profile(mut profile : Profile) -> Result<u32, ()> {
    let person = caller();
    assert!(person != Principal::anonymous(), "You must be signed in");
    let principal_id = person.to_text();
    let profile_exist = PROFILE_STORE.with(|store| {
        let binding = store.borrow();
        binding.contains_key(&principal_id)
    });

    assert!(profile_exist, "You must be registered");
    PROFILE_STORE.with(|store|{
        let mut binding = store.borrow_mut();
        let prev_profile = binding.get(&principal_id).unwrap();
        profile.email = prev_profile.email.clone();
        binding.insert(principal_id, profile);
        return  Result::Ok(200);
    })
}

fn bls12_381_test_key_1() -> VetKDKeyId {
    VetKDKeyId {
        curve: VetKDCurve::Bls12_381,
        name: "test_key_1".to_string(),
    }
}

fn vetkd_system_api_canister_id() -> CanisterId {
    CanisterId::from_str(VETKD_SYSTEM_API_CANISTER_ID).expect("failed to create canister ID")
}

fn debug_println_caller(method_name: &str) {
    ic_cdk::println!(
        "{}: caller: {} (isAnonymous: {})",
        method_name,
        ic_cdk::caller().to_text(),
        ic_cdk::caller() == candid::Principal::anonymous()
    );
}


fn is_management() {
    let caller = caller();
    assert!(caller != Principal::anonymous(), "Caller is anonymous");
    assert!(caller == MGMT, "You must be management");
}

generate_ic_model!(Verification, is_management, VERIFICATION_STORE);
generate_ic_model!(Message, is_management, MESSAGE_STORE);
generate_ic_model!(TWOFA, is_management, TWOFA_STORE);
// generate_ic_model!(Profile, is_management, PROFILE_STORE);
ic_cdk::export_candid!();
