// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

/// @notice An ownerless index of service ADVERTISEMENTS: where an operator says its directory, checker, storage adapter,
/// DNS replica or release/artifact replica can be reached. It exists so a first user who knows only this contract's
/// address (and some RPCs) can find candidate services without anyone's approval, name reservation or mutable list.
///
/// What it is NOT. An ad is a self-description by whoever holds the operator key. It proves nothing about honest content,
/// organizational independence, an accepted host owner or a checker's authority; readers return ads as untrusted
/// candidates, and every existing cryptographic policy (signed provider records, owner policies, pinned checkers) still
/// decides what is used. Nothing here is consulted for admission.
///
/// Rules. Every ad belongs to (operator, slot), at most MAX_SLOTS per operator. Only the operator - directly (an EOA or a
/// smart-contract wallet calling from its own address), or by an EIP-712 signature bound to this chain id and this
/// contract (an EOA's secp256k1 signature, or an ERC-1271 wallet's isValidSignature) - can publish, replace or withdraw it. Each change uses a
/// strictly higher per-slot sequence, which survives withdrawal, so an old signature can never be replayed. Every ad
/// expires within MAX_TTL; anyone may remove an ad that has ALREADY expired (it is void either way), nobody may remove a
/// live one. There is no owner, administrator, pause, upgrade or global delete. Storage per ad is bounded (MAX_ENDPOINTS
/// endpoints of at most MAX_ENDPOINT_BYTES printable ASCII bytes, plus a 32-byte content hash of an optional descriptor),
/// and enumeration is by kind in pages of at most MAX_PAGE.
contract EnclaveServiceIndex {
    uint8 public constant MAX_SLOTS = 8;
    uint256 public constant MAX_ENDPOINTS = 4;
    uint256 public constant MAX_ENDPOINT_BYTES = 256;
    uint64 public constant MAX_TTL = 90 days;
    uint256 public constant MAX_PAGE = 64;

    struct Ad {
        address operator;
        uint8 slot;
        uint16 kind;          // what the service is (readers name the kinds they understand; 0 is invalid)
        uint16 version;       // the ad's format version (readers skip versions they do not understand; 0 is invalid)
        uint64 sequence;
        uint64 expiresAt;
        uint64 updatedAt;
        bytes32 descriptor;   // sha256 of a bounded descriptor document, or zero
        string[] endpoints;
    }

    bytes32 public constant PUBLISH_TYPEHASH = keccak256(
        "Publish(address operator,uint8 slot,uint16 kind,uint16 version,uint64 sequence,uint64 expiresAt,bytes32 descriptor,string[] endpoints)");
    bytes32 public constant WITHDRAW_TYPEHASH = keccak256("Withdraw(address operator,uint8 slot,uint64 sequence)");
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant NAME_HASH = keccak256("EnclaveServiceIndex");
    bytes32 private constant VERSION_HASH = keccak256("1");
    uint256 private constant HALF_N = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e; // isValidSignature(bytes32,bytes)
    uint256 public constant MAX_SIGNATURE_BYTES = 2048;
    uint256 public constant ERC1271_GAS = 500_000;

    mapping(bytes32 => Ad) private ads;
    /// @notice The last sequence used for (operator, slot): a publish or withdraw must exceed it. Kept after withdrawal.
    mapping(address => mapping(uint8 => uint64)) public sequenceOf;
    mapping(uint16 => bytes32[]) private byKind;
    mapping(bytes32 => uint256) private position; // 1-based index into byKind[ads[key].kind]; 0 = not listed

    event Published(address indexed operator, uint8 slot, uint16 indexed kind, uint64 sequence, uint64 expiresAt, bytes32 descriptor);
    event Withdrawn(address indexed operator, uint8 slot, uint64 sequence);
    event Pruned(address indexed operator, uint8 slot, uint64 sequence);

    function publish(uint8 slot, uint16 kind, uint16 version, uint64 sequence, uint64 expiresAt, bytes32 descriptor,
                     string[] calldata endpoints) external {
        _publish(msg.sender, slot, kind, version, sequence, expiresAt, descriptor, endpoints);
    }

    /// @notice Publish for `operator` with its EIP-712 signature; anyone may submit (and pay for) it.
    function publishFor(address operator, uint8 slot, uint16 kind, uint16 version, uint64 sequence, uint64 expiresAt,
                        bytes32 descriptor, string[] calldata endpoints, bytes calldata signature) external {
        require(_validSignature(operator, publishDigest(operator, slot, kind, version, sequence, expiresAt, descriptor, endpoints), signature),
                "not signed by operator");
        _publish(operator, slot, kind, version, sequence, expiresAt, descriptor, endpoints);
    }

    /// @notice Remove your own ad (or only burn the sequence, revoking a signed publish not yet submitted).
    function withdraw(uint8 slot, uint64 sequence) external {
        _withdraw(msg.sender, slot, sequence);
    }

    function withdrawFor(address operator, uint8 slot, uint64 sequence, bytes calldata signature) external {
        require(_validSignature(operator, withdrawDigest(operator, slot, sequence), signature), "not signed by operator");
        _withdraw(operator, slot, sequence);
    }

    /// @notice Remove an ad that has already expired. A live ad cannot be removed by anyone but its operator.
    function prune(address operator, uint8 slot) external {
        bytes32 key = _key(operator, slot);
        Ad storage a = ads[key];
        require(a.operator != address(0), "no ad");
        require(a.expiresAt <= block.timestamp, "ad is live");
        emit Pruned(operator, slot, a.sequence);
        _unlist(key);
        delete ads[key];
    }

    function get(address operator, uint8 slot) external view returns (Ad memory) {
        return ads[_key(operator, slot)];
    }

    function count(uint16 kind) external view returns (uint256) {
        return byKind[kind].length;
    }

    /// @notice Up to `limit` (at most MAX_PAGE) ads of `kind` from index `start`, expired ones included (readers filter by
    /// the block's timestamp), and the total listed. Read every page at ONE block: order changes as ads come and go.
    function page(uint16 kind, uint256 start, uint256 limit) external view returns (Ad[] memory out, uint256 total) {
        bytes32[] storage keys = byKind[kind];
        total = keys.length;
        if (limit > MAX_PAGE) limit = MAX_PAGE;
        if (start >= total) return (new Ad[](0), total);
        uint256 n = total - start < limit ? total - start : limit;
        out = new Ad[](n);
        for (uint256 i = 0; i < n; i++) out[i] = ads[keys[start + i]];
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)));
    }

    function publishDigest(address operator, uint8 slot, uint16 kind, uint16 version, uint64 sequence, uint64 expiresAt,
                           bytes32 descriptor, string[] calldata endpoints) public view returns (bytes32) {
        bytes32[] memory h = new bytes32[](endpoints.length);
        for (uint256 i = 0; i < endpoints.length; i++) h[i] = keccak256(bytes(endpoints[i]));
        bytes32 structHash = keccak256(abi.encode(PUBLISH_TYPEHASH, operator, slot, kind, version, sequence, expiresAt, descriptor,
                                                  keccak256(abi.encodePacked(h))));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function withdrawDigest(address operator, uint8 slot, uint64 sequence) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(WITHDRAW_TYPEHASH, operator, slot, sequence))));
    }

    function _publish(address operator, uint8 slot, uint16 kind, uint16 version, uint64 sequence, uint64 expiresAt,
                      bytes32 descriptor, string[] calldata endpoints) private {
        require(operator != address(0), "operator required");
        require(slot < MAX_SLOTS, "slot out of range");
        require(kind != 0 && version != 0, "kind and version required");
        require(sequence > sequenceOf[operator][slot], "stale sequence");
        require(expiresAt > block.timestamp && expiresAt <= block.timestamp + MAX_TTL, "expiry out of range");
        require(endpoints.length > 0 && endpoints.length <= MAX_ENDPOINTS, "1 to 4 endpoints");
        for (uint256 i = 0; i < endpoints.length; i++) {
            bytes calldata e = bytes(endpoints[i]);
            require(e.length > 0 && e.length <= MAX_ENDPOINT_BYTES, "endpoint length");
            for (uint256 j = 0; j < e.length; j++) require(uint8(e[j]) > 0x20 && uint8(e[j]) < 0x7f, "endpoint must be printable ASCII");
        }
        bytes32 key = _key(operator, slot);
        Ad storage a = ads[key];
        if (a.operator != address(0) && a.kind != kind) _unlist(key);
        if (position[key] == 0) { byKind[kind].push(key); position[key] = byKind[kind].length; }
        sequenceOf[operator][slot] = sequence;
        a.operator = operator;
        a.slot = slot;
        a.kind = kind;
        a.version = version;
        a.sequence = sequence;
        a.expiresAt = expiresAt;
        a.updatedAt = uint64(block.timestamp);
        a.descriptor = descriptor;
        delete a.endpoints;
        for (uint256 i = 0; i < endpoints.length; i++) a.endpoints.push(endpoints[i]);
        emit Published(operator, slot, kind, sequence, expiresAt, descriptor);
    }

    function _withdraw(address operator, uint8 slot, uint64 sequence) private {
        require(slot < MAX_SLOTS, "slot out of range");
        require(sequence > sequenceOf[operator][slot], "stale sequence");
        sequenceOf[operator][slot] = sequence;
        bytes32 key = _key(operator, slot);
        if (ads[key].operator != address(0)) { _unlist(key); delete ads[key]; }
        emit Withdrawn(operator, slot, sequence);
    }

    function _unlist(bytes32 key) private {
        uint256 p = position[key];
        if (p == 0) return;
        bytes32[] storage keys = byKind[ads[key].kind];
        bytes32 last = keys[keys.length - 1];
        keys[p - 1] = last;
        position[last] = p;
        keys.pop();
        position[key] = 0;
    }

    function _key(address operator, uint8 slot) private pure returns (bytes32) {
        return keccak256(abi.encode(operator, slot));
    }

    /// @dev The operator's signature over `digest`: a low-s 65-byte secp256k1 signature by the operator's key, or - for an
    /// operator with code (a smart-contract wallet) - its ERC-1271 isValidSignature answer, asked by a STATICCALL with a
    /// fixed gas budget, reading at most 32 bytes back. The digest already binds chain id, this contract and the sequence,
    /// so a wallet's approval cannot be replayed elsewhere or later.
    function _validSignature(address operator, bytes32 digest, bytes calldata sig) private view returns (bool) {
        if (operator == address(0) || sig.length > MAX_SIGNATURE_BYTES) return false;
        if (_signer(digest, sig) == operator) return true;
        if (operator.code.length == 0) return false;
        bytes memory data = abi.encodeWithSelector(ERC1271_MAGIC, digest, sig);
        bool ok;
        uint256 size;
        bytes32 word;
        uint256 budget = ERC1271_GAS;
        assembly ("memory-safe") {
            ok := staticcall(budget, operator, add(data, 0x20), mload(data), 0x00, 0x20)
            size := returndatasize()
            word := mload(0x00)
        }
        return ok && size >= 32 && word == bytes32(ERC1271_MAGIC);
    }

    /// @dev A 65-byte (r, s, v) secp256k1 signature, low s only; address(0) on anything else.
    function _signer(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (uint256(s) > HALF_N || (v != 27 && v != 28)) return address(0);
        return ecrecover(digest, v, r, s);
    }
}
