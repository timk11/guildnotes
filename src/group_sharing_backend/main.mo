import Text "mo:base/Text";
import Bool "mo:base/Bool";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Array "mo:base/Array";
import HashMap "mo:base/HashMap";
import Result "mo:base/Result";
import Hex "./utils/Hex";

shared(msg) actor class() {
  type Role = { #Owner; #Admin; #Conqueror; #Explorer; #Player };
  type UserID = Text;
  type EncryptedMSK = Text;
  
  let users = HashMap.HashMap<UserID, Role>(3, Text.equal, Text.hash);
  let userKeys = HashMap.HashMap<UserID, EncryptedMSK>(3, Text.equal, Text.hash);
  let contentMap = HashMap.HashMap<Text, Text>(5, Text.equal, Text.hash);

  let canister_owner = msg.caller;
  var init_status : Bool = false;

  public shared func checkInitStatus() : async Bool {
    return init_status;
  };

  public shared func checkOwnerId() : async [Nat8] {
    // assert (init_status == false);
    let canister_owner_blob = Principal.toBlob(canister_owner);
    let canister_owner_array = Blob.toArray(canister_owner_blob);
    return canister_owner_array;
  };

  public shared func canisterOwnerText(): async Text { // delete after testing
    return Principal.toText(canister_owner);
  };

  public shared func initialise (encrypted_msk: EncryptedMSK) : async Bool {
    if (init_status == false) {
      users.put(Principal.toText(canister_owner), #Owner);
      userKeys.put(Principal.toText(canister_owner), encrypted_msk);
      init_status := true;
      return true;
    };
    return false;
  };

  public shared func addSecondOwner (owner2_id : Text, encrypted_msk : EncryptedMSK) : async Bool {
    if (users.size() < 2) {
      users.put(owner2_id, #Owner);
      userKeys.put(owner2_id, encrypted_msk);
      return true;
    };
    return false;
  };
    
  private func toText(r : Role) : Text {
    switch r {
      case (#Owner) { "Owner" };
      case (#Admin) { "Admin" };
      case (#Conqueror) { "Conqueror" };
      case (#Explorer) { "Explorer" };
      case (#Player) { "Player" };
    };
  };

  // --LOGIN--

  public shared({ caller }) func whoami(): async Text {
    return Principal.toText(caller);
  };

  // --ROLES--

  public shared(Role) func getUserRole(userId : UserID) : async ?Role {
    return users.get(userId);
  };

  public shared(Role) func getEncryptedMSK(userId : UserID) : async ?EncryptedMSK {
    return userKeys.get(userId);
  };


  public shared func getUsersWithRole(role : Role) : async Text {
    // Find all users with the specified role
    let map2 = HashMap.mapFilter<UserID, Role, Role>(
      users,
      Text.equal,
      Text.hash,
      func (k, v) = if (v == role) { ?role } else { null }
    );
    var keys = "";
    for (key in map2.keys()) {
      keys := keys # "<br>";
      keys := keys # key;
    };
    return keys;
  };

  public shared({ caller }) func assignRole(userId : UserID, role : Role, encrypted_msk : EncryptedMSK) : async Bool {
    // check if valid role has been selected
    if ((role == #Conqueror) or (role == #Explorer) or (role == #Player)) {
      // Check if the caller is the canister owner or has the Owner or Admin role
      if ((caller == canister_owner) or (userHasRole(caller, #Owner)) or (userHasRole(caller, #Admin))) {
        // Update or add the user's role
        users.put(userId, role);
        userKeys.put(userId, encrypted_msk);
        return true;
      };
      return false;
    };
    return false;
  };

  public shared({ caller }) func appointOwner(userId : UserID, encrypted_msk : EncryptedMSK) : async Bool {
    // Check if the caller is the canister owner or has the Owner role
    if ((caller == canister_owner) or (userHasRole(caller, #Owner))) {
      // Update or add the user's role
      users.put(userId, #Owner);
      userKeys.put(userId, encrypted_msk);
      return true;
    };
    return false;
  };

  public shared({ caller }) func appointAdmin(userId : UserID, encrypted_msk : EncryptedMSK) : async Bool {
    // Check if the caller is the canister owner or has the Owner role
    if ((caller == canister_owner) or (userHasRole(caller, #Owner))) {
      // Update or add the user's role
      users.put(userId, #Admin);
      userKeys.put(userId, encrypted_msk);
      return true;
    };
    return false;
  };

  public shared({ caller }) func demoteAdmin(userId : UserID, encrypted_msk : EncryptedMSK) : async Bool {
    // Check if the caller is the canister owner or has the Owner role
    if ((caller == canister_owner) or (userHasRole(caller, #Owner))) {
      // Update the user's role
      users.put(userId, #Player);
      userKeys.put(userId, encrypted_msk);
      return true;
    };
    return false;
  };

  public shared({ caller }) func deleteUser(userId : UserID) : async Bool {
    // Owners cannot be deleted
    if (userHasRole(Principal.fromText(userId), #Owner)) {
      return false;
    };
    // Check if the caller is the canister owner or has the Owner role
    if ((caller == canister_owner) or (userHasRole(caller, #Owner))) {
      users.delete(userId);
      return true;
    };
    return false;
  };

  private func userHasRole(user : Principal, role : Role) : Bool {
    let callerId = Principal.toText(user);
    return (users.get(callerId) == ?role);
  };

  // --KEYS--

  // Only the ecdsa methods in the IC management canister is required here.
  type VETKD_SYSTEM_API = actor {
    vetkd_public_key : ({
      canister_id : ?Principal;
      derivation_path : [Blob];
      key_id : { curve: { #bls12_381; } ; name: Text };
    }) -> async ({ public_key : Blob; });
    vetkd_encrypted_key : ({
      public_key_derivation_path : [Blob];
      derivation_id : Blob;
      key_id : { curve: { #bls12_381; } ; name: Text };
      encryption_public_key : Blob;
    }) -> async ({ encrypted_key : Blob });
  };

  let vetkd_system_api : VETKD_SYSTEM_API = actor("s55qq-oqaaa-aaaaa-aaakq-cai");

  public shared({ caller }) func app_vetkd_public_key(derivation_path_text : Text) : async Text {
    let { public_key } = await vetkd_system_api.vetkd_public_key({
      canister_id = null;
      derivation_path = Array.make(Text.encodeUtf8(derivation_path_text));
      key_id = { curve = #bls12_381; name = "test_key_1" };
    });
    Hex.encode(Blob.toArray(public_key))
  };

  public shared ({ caller }) func app_vetkd_encrypted_key(encryption_public_key : Blob, derivation_id_text : Text, derivation_path_text : Text) : async Text {
    let { encrypted_key } = await vetkd_system_api.vetkd_encrypted_key({
      derivation_id = Text.encodeUtf8(derivation_id_text);
      public_key_derivation_path = Array.make(Text.encodeUtf8(derivation_path_text));
      key_id = { curve = #bls12_381; name = "test_key_1" };
      encryption_public_key;
    });
    Hex.encode(Blob.toArray(encrypted_key));
  };

  public shared({ caller }) func symmetric_key_verification_key(role: Role): async Text {
    let { public_key } = await vetkd_system_api.vetkd_public_key({
      canister_id = null;
      derivation_path = Array.make(Text.encodeUtf8(toText(role)));
      key_id = { curve = #bls12_381; name = "test_key_1" };
    });
    Hex.encode(Blob.toArray(public_key))
  };

  public shared ({ caller }) func encrypted_symmetric_key_for_caller(encryption_public_key : Blob, role: Role) : async Text {
    let { encrypted_key } = await vetkd_system_api.vetkd_encrypted_key({
      derivation_id = Principal.toBlob(caller);
      public_key_derivation_path = Array.make(Text.encodeUtf8(toText(role)));
      key_id = { curve = #bls12_381; name = "test_key_1" };
      encryption_public_key;
    });
    Hex.encode(Blob.toArray(encrypted_key));
  };

  public shared ({ caller }) func encrypted_symmetric_key_for_canister_owner(encryption_public_key : Blob, derivation_path_text : Text) : async Text {
    let { encrypted_key } = await vetkd_system_api.vetkd_encrypted_key({
      derivation_id = Principal.toBlob(canister_owner);
      public_key_derivation_path = Array.make(Text.encodeUtf8(derivation_path_text));
      key_id = { curve = #bls12_381; name = "test_key_1" };
      encryption_public_key;
    });
    Hex.encode(Blob.toArray(encrypted_key));
  };

  // --CONTENT--

  public shared({ caller }) func addContent(content : Text, role : Role) : async Bool {
    // Check if the caller has the Owner or Admin role
    if ((userHasRole(caller, #Owner)) or (userHasRole(caller, #Admin))) {
      contentMap.put(toText(role), content);
      return true;
      };
    return false;
  };

  public shared func getContent(userId : UserID) : async ?Text {
    // Find the role for the user
    let role = switch (users.get(userId)) {
      case (?#Owner) { "Owner" };
      case (?#Admin) { "Admin" };
      case (?#Conqueror) { "Conqueror" };
      case (?#Explorer) { "Explorer" };
      case (?#Player) { "Player" };
      case (null) { "none" };
    };
    return contentMap.get(role);
  };

  public shared({ caller }) func getContentByRole(role : Role) : async ?Text {
    // Check if the caller has the Owner or Admin role
    if ((userHasRole(caller, #Owner)) or (userHasRole(caller, #Admin))) {
      // Find the content for the role
      return contentMap.get(toText(role));
    };
    return null;
  };


  // UPGRADE HOOKS?
  // https://internetcomputer.org/docs/current/motoko/main/upgrades/

};
