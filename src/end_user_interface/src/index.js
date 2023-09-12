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

// Function to get decrypted content for a selected role
document.getElementById("getContent").addEventListener("submit", async (e) => {
  e.preventDefault();
  const button = e.target.querySelector("button");
  button.setAttribute("disabled", true);
  document.getElementById("show_content").innerText = "Fetching content";
  const callerId = app_backend_principal.toText();
  const callerRole = await actor.getUserRole(callerId);
  const callerRoleText = (JSON.stringify(callerRole[0])).slice(2, -7);
  const decrypt_key = await get_aes_256_gcm_key_from_text(callerId, callerRoleText);
  const caller_enc_msk = await actor.getEncryptedMSK(callerId);
  const _decoded_msk = await aes_gcm_decrypt(caller_enc_msk, decrypt_key);
  console.log("_decoded_msk =", _decoded_msk);
  const _msk = hex_decode(_decoded_msk);
  console.log("_msk =", _msk);
  button.removeAttribute("disabled");
  const _ciphertext_hex = await actor.getContent(callerId);
  console.log("_ciphertext_hex =", _ciphertext_hex);
  let content;
  if (_ciphertext_hex != null && _ciphertext_hex != "") {
    const content_hex = await aes_gcm_decrypt(_ciphertext_hex, _msk);
    content = Buffer.from(hex_decode(content_hex)).toString();
  } else {
    content = "";
  };
  document.getElementById("show_content").innerHTML = content;
});

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

async function aes_gcm_encrypt(message, rawKey) {
  const iv = window.crypto.getRandomValues(new Uint8Array(16)); // unique per message
  const aes_key = await window.crypto.subtle.importKey("raw", rawKey, "AES-CTR", false, ["encrypt"]);
  const message_encoded = hex_decode(message);
  console.log("message_encoded =", message_encoded);
  const ciphertext_buffer = await window.crypto.subtle.encrypt(
    { name: "AES-CTR", counter: iv, length: 64 },
    aes_key,
    message_encoded
  );
  console.log("ciphertext_buffer =", ciphertext_buffer);
  const ciphertext = new Uint8Array(ciphertext_buffer);
  console.log("ciphertext =", ciphertext);
  var iv_and_ciphertext = new Uint8Array(iv.length + ciphertext.length);
  iv_and_ciphertext.set(iv, 0);
  iv_and_ciphertext.set(ciphertext, iv.length);
  return hex_encode(iv_and_ciphertext);
};

async function aes_gcm_decrypt(ciphertext_hex, rawKey) {
  const iv_and_ciphertext = hex_decode(ciphertext_hex);
  console.log("iv_and_ciphertext =", iv_and_ciphertext);
  const iv = iv_and_ciphertext.subarray(0, 16); // unique per message
  console.log("iv =", iv);
  const ciphertext = iv_and_ciphertext.subarray(16);
  console.log("ciphertext =", ciphertext);
  const aes_key = await window.crypto.subtle.importKey("raw", rawKey, "AES-CTR", false, ["decrypt"]);
  console.log("aes_key =", aes_key);
  console.log(typeof aes_key);
  let decrypted = await window.crypto.subtle.decrypt(
    { name: "AES-CTR", counter: iv, length: 64 },
    aes_key,
    ciphertext
  );
  console.log("decrypted =", decrypted);
  return hex_encode(decrypted);
};