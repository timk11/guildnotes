import { Principal } from "@dfinity/principal";
import { Actor, HttpAgent } from "@dfinity/agent";
import { AuthClient } from "@dfinity/auth-client";
import { idlFactory } from "../../declarations/group_sharing_backend"; // /group_sharing_backend.did.js";
import * as vetkd from "ic-vetkd-utils";
import { group_sharing_backend } from "../../declarations/group_sharing_backend";

let actor = group_sharing_backend;
let app_backend_principal = await Actor.agentOf(actor).getPrincipal();
const identity_canister_id = process.env.INTERNET_IDENTITY_CANISTER_ID;

const hex_decode = (hexString) =>
  Uint8Array.from(String(hexString).match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
function hex_encode(bytes) { // source: https://stackoverflow.com/a/40031979
  return [...new Uint8Array(bytes)]
      .map(x => x.toString(16).padStart(2, '0'))
      .join('');
};

const init_status = await actor.checkInitStatus();
console.log("init_status =", init_status);
if (init_status == false) {
  const randvals = window.crypto.getRandomValues(new Uint8Array(32));
  const randtext = hex_encode(randvals);
  let msk = await get_aes_256_gcm_key_from_text(randtext, "master_key");
  let temp_key = await get_aes_256_gcm_key_for_canister_owner();
  let decoded_msk = hex_encode(msk);
  let encrypted_msk = await aes_gcm_encrypt(decoded_msk, temp_key);
  const intialised = await actor.initialise(encrypted_msk);
  console.log("intialised =", intialised);
  // For local deployment and testing
  temp_key = await get_aes_256_gcm_key_from_text("2vxsx-fae", "Owner");
  encrypted_msk = await aes_gcm_encrypt(decoded_msk, temp_key);
  let owner2_added = await actor.addSecondOwner("2vxsx-fae", encrypted_msk);
  // For deployment to IC (comment 3 lines above, uncomment next 3 lines and replace with your own principal ID)
  // temp_key = await get_aes_256_gcm_key_from_text("mypri-ncipa-lid", "Owner");
  // encrypted_msk = await aes_gcm_encrypt(hex_encode(msk), temp_key);
  // let owner2_added = await actor.addSecondOwner("mypri-ncipa-lid", encrypted_msk);
  console.log("owner2_added =", owner2_added);
  msk = null;
  decoded_msk = null;
  encrypted_msk = null;
};

// Internet Identity login
const init = async () => {
  let authClient = await AuthClient.create();
  document.getElementById("login").addEventListener("click", async (e) => {
    e.preventDefault();
    await authClient.login({
      onSuccess: async () => {
        const identity = authClient.getIdentity();
        const agent = new HttpAgent({ identity });
        await agent.fetchRootKey();
        actor = Actor.createActor(idlFactory, {
          agent,
          canisterId: process.env.GROUP_SHARING_BACKEND_CANISTER_ID,
        });
        app_backend_principal = identity.getPrincipal();
      },
      identityProvider: `http://localhost:4943?canisterId=${identity_canister_id}`
    });
  });
};

init();

// whoami function
document.getElementById("whoami").addEventListener("click", async () => {
  const whoamiResult = await actor.whoami();
  document.getElementById("whoami_result").innerText = "You are logged in as " + whoamiResult;
  return false;
});

// Function to show user role
document.getElementById("get_user_role").addEventListener("submit", async (e) => {
  e.preventDefault();
  const userId = document.getElementById("user_id").value; // principal ID
  const userRole = await actor.getUserRole(userId);
  document.getElementById("user_role").innerText = "Role: " + JSON.stringify(userRole);
  return false;
});

// Function to show users with role
document.getElementById("get_users_with_role").addEventListener("submit", async (e) => {
  e.preventDefault();
  document.getElementById("users_with_role").innerText = "Checking";
  const roleInput = document.getElementById("role_input").value;
  const usersWithRole = await actor.getUsersWithRole(JSON.parse(roleInput));
  document.getElementById("users_with_role").innerHTML = usersWithRole;
});

// Function to assign role to a user
document.getElementById("assignRole").addEventListener("submit", async (e) => {
  e.preventDefault();
  const userId = document.getElementById("user_id2").value;
  const roleInput = document.getElementById("role_input2").value;
  const callerId = app_backend_principal.toText();
  const callerRole = await actor.getUserRole(callerId);
  const callerRoleText = (JSON.stringify(callerRole[0])).slice(2, -7);
  const decrypt_key = await get_aes_256_gcm_key_from_text(callerId, callerRoleText);
  const caller_enc_msk = await actor.getEncryptedMSK(callerId);
  const _decoded_msk = await aes_gcm_decrypt(caller_enc_msk, decrypt_key);
  const _msk = hex_decode(_decoded_msk);      //
  const encrypt_key = await get_aes_256_gcm_key_from_text(userId, roleInput.slice(2, -7));
  const _encrypted_msk = await aes_gcm_encrypt(_decoded_msk, encrypt_key);
  await actor.assignRole(userId, JSON.parse(roleInput), _encrypted_msk);
  // Get and display the updated role for the user
  const updatedRole = await actor.getUserRole(userId);
  document.getElementById("updated_role").innerText = "Role: " + JSON.stringify(updatedRole).slice(3, -8);
});

// Function to appoint new Admin (Owner-only function)
document.getElementById("appointAdmin").addEventListener("submit", async (e) => {
  e.preventDefault();
  const userId = document.getElementById("user_id5").value;
  const callerId = app_backend_principal.toText();
  const callerRole = await actor.getUserRole(callerId);
  const callerRoleText = (JSON.stringify(callerRole[0])).slice(2, -7);
  const decrypt_key = await get_aes_256_gcm_key_from_text(callerId, callerRoleText);
  const caller_enc_msk = await actor.getEncryptedMSK(callerId);
  const _decoded_msk = await aes_gcm_decrypt(caller_enc_msk, decrypt_key);
  const encrypt_key = await get_aes_256_gcm_key_from_text(userId, "Admin");
  const _encrypted_msk = await aes_gcm_encrypt(_decoded_msk, encrypt_key);
  await actor.appointAdmin(userId, _encrypted_msk);
  // Get and display the updated role for the user
  const updatedRole = await actor.getUserRole(userId);
  document.getElementById("aa_result").innerText = "Role: " + JSON.stringify(updatedRole).slice(3, -8);
});

// Function to appoint new Owner (Owner-only function)
document.getElementById("appointOwner").addEventListener("submit", async (e) => {
  e.preventDefault();
  const userId = document.getElementById("user_id6").value;
  const callerId = app_backend_principal.toText();
  const callerRole = await actor.getUserRole(callerId);
  const callerRoleText = (JSON.stringify(callerRole[0])).slice(2, -7);
  const decrypt_key = await get_aes_256_gcm_key_from_text(callerId, callerRoleText);
  const caller_enc_msk = await actor.getEncryptedMSK(callerId);
  const _decoded_msk = await aes_gcm_decrypt(caller_enc_msk, decrypt_key);
  const encrypt_key = await get_aes_256_gcm_key_from_text(userId, "Owner");
  const _encrypted_msk = await aes_gcm_encrypt(_decoded_msk, encrypt_key);
  await actor.appointOwner(userId, _encrypted_msk);
  // Get and display the updated role for the user
  const updatedRole = await actor.getUserRole(userId);
  document.getElementById("ao_result").innerText = "Role: " + JSON.stringify(updatedRole).slice(3, -8);
});

// Function to demote an Admin (Owner-only function)
document.getElementById("demoteAdmin").addEventListener("submit", async (e) => {
  e.preventDefault();
  const userId = document.getElementById("user_id7").value;
  const callerId = app_backend_principal.toText();
  const callerRole = await actor.getUserRole(callerId);
  const callerRoleText = (JSON.stringify(callerRole[0])).slice(2, -7);
  const decrypt_key = await get_aes_256_gcm_key_from_text(callerId, callerRoleText);
  const caller_enc_msk = await actor.getEncryptedMSK(callerId);
  const _decoded_msk = await aes_gcm_decrypt(caller_enc_msk, decrypt_key);
  const encrypt_key = await get_aes_256_gcm_key_from_text(userId, "Player");
  const _encrypted_msk = await aes_gcm_encrypt(_decoded_msk, encrypt_key);
  await actor.demoteAdmin(userId, _encrypted_msk);
  // Get and display the updated role for the user
  const updatedRole = await actor.getUserRole(userId);
  document.getElementById("da_result").innerText = "Role: " + JSON.stringify(updatedRole).slice(3, -8);
});

// Function to delete a user (Owner-only function)
document.getElementById("deleteUser").addEventListener("submit", async (e) => {
  e.preventDefault();
  const userId = document.getElementById("user_id8").value;
  await actor.deleteUser(userId);
  // Get and display the updated role for the user
  document.getElementById("du_result").innerText = userId + " is deleted";
});

// Function to update encrypted content for the user's role
document.getElementById("updateContent").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  document.getElementById("updated_content").innerText = "Updating content";
  const roleInput = document.getElementById("role_input4").value;
  const callerId = app_backend_principal.toText();
  const callerRole = await actor.getUserRole(callerId);
  const callerRoleText = (JSON.stringify(callerRole[0])).slice(2, -7);
  const decrypt_key = await get_aes_256_gcm_key_from_text(callerId, callerRoleText);
  const caller_enc_msk = await actor.getEncryptedMSK(callerId);
  const _decoded_msk = await aes_gcm_decrypt(caller_enc_msk, decrypt_key);
  const _msk = hex_decode(_decoded_msk);
  button.removeAttribute("disabled");
  const content_input = document.getElementById("content_input").value;
  const content_input_hex = hex_encode(Buffer.from(content_input));
  const _ciphertext_hex = await aes_gcm_encrypt(content_input_hex, _msk);
  await actor.addContent(_ciphertext_hex, JSON.parse(roleInput));
  document.getElementById("updated_content").innerText = "Content updated";
});

// Function to get decrypted content for a selected role
document.getElementById("getContent").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  document.getElementById("show_content").innerText = "Fetching content";
  const roleInput = document.getElementById("role_input3").value;
  const displayAs = document.getElementById("display_as").value;
  const callerId = app_backend_principal.toText();
  const callerRole = await actor.getUserRole(callerId);
  const callerRoleText = (JSON.stringify(callerRole[0])).slice(2, -7);
  const decrypt_key = await get_aes_256_gcm_key_from_text(callerId, callerRoleText);
  const caller_enc_msk = await actor.getEncryptedMSK(callerId);
  const _decoded_msk = await aes_gcm_decrypt(caller_enc_msk, decrypt_key);
  const _msk = hex_decode(_decoded_msk);
  button.removeAttribute("disabled");
  const _ciphertext_hex = await actor.getContentByRole(JSON.parse(roleInput));
  let content;
  if (_ciphertext_hex != null && _ciphertext_hex != "") {
    const content_hex = await aes_gcm_decrypt(_ciphertext_hex, _msk);
    content = Buffer.from(hex_decode(content_hex)).toString();
  } else {
    content = "";
  };
  if (displayAs == "HTML") {
    document.getElementById("show_content").innerHTML = content;
  } else {
    document.getElementById("show_content").innerText = content;
  };
});

async function get_aes_256_gcm_key(roleInput) {
  const seed = window.crypto.getRandomValues(new Uint8Array(32));
  const tsk = new vetkd.TransportSecretKey(seed);
  const ek_bytes_hex = await actor.encrypted_symmetric_key_for_caller(tsk.public_key(), JSON.parse(roleInput));
  const pk_bytes_hex = await actor.symmetric_key_verification_key(JSON.parse(roleInput));
  return tsk.decrypt_and_hash(
    hex_decode(ek_bytes_hex),
    hex_decode(pk_bytes_hex),
    app_backend_principal.toUint8Array(),
    32,
    new TextEncoder().encode("aes-256-gcm")
  );
};

async function get_aes_256_gcm_key_from_text(deriv_id_text, deriv_path_text) {
  const seed = window.crypto.getRandomValues(new Uint8Array(32));
  const tsk = new vetkd.TransportSecretKey(seed);
  const ek_bytes_hex = await actor.app_vetkd_encrypted_key(tsk.public_key(), deriv_id_text, deriv_path_text);
  const pk_bytes_hex = await actor.app_vetkd_public_key(deriv_path_text);
  return tsk.decrypt_and_hash(
    hex_decode(ek_bytes_hex),
    hex_decode(pk_bytes_hex),
    new TextEncoder().encode(deriv_id_text), // this needs fixing
    32,
    new TextEncoder().encode("aes-256-gcm")
  );
};

async function get_aes_256_gcm_key_for_canister_owner() {
  const seed = window.crypto.getRandomValues(new Uint8Array(32));
  const tsk = new vetkd.TransportSecretKey(seed);
  const ek_bytes_hex = await actor.encrypted_symmetric_key_for_canister_owner(tsk.public_key(), "Owner");
  const pk_bytes_hex = await actor.app_vetkd_public_key("Owner");
  const canister_owner_array = await actor.checkOwnerId();
  return tsk.decrypt_and_hash(
    hex_decode(ek_bytes_hex),
    hex_decode(pk_bytes_hex),
    canister_owner_array,
    32,
    new TextEncoder().encode("aes-256-gcm")
  );
};

async function aes_gcm_encrypt(message, rawKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(16)); // unique per message
  const aes_key = await window.crypto.subtle.importKey("raw", rawKey, "AES-CTR", false, ["encrypt"]);
  const message_encoded = hex_decode(message);
  const ciphertext_buffer = await window.crypto.subtle.encrypt(
    { name: "AES-CTR", counter: iv, length: 64 },
    aes_key,
    message_encoded
  );
  const ciphertext = new Uint8Array(ciphertext_buffer);
  var iv_and_ciphertext = new Uint8Array(iv.length + ciphertext.length);
  iv_and_ciphertext.set(iv, 0);
  iv_and_ciphertext.set(ciphertext, iv.length);
  return hex_encode(iv_and_ciphertext);
};

async function aes_gcm_decrypt(ciphertext_hex, rawKey) {
  const iv_and_ciphertext = hex_decode(ciphertext_hex);
  const iv = iv_and_ciphertext.subarray(0, 16); // unique per message
  const ciphertext = iv_and_ciphertext.subarray(16);
  const aes_key = await window.crypto.subtle.importKey("raw", rawKey, "AES-CTR", false, ["decrypt"]);
  let decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-CTR", counter: iv, length: 64 },
    aes_key,
    ciphertext
  );
  return hex_encode(decrypted);
};