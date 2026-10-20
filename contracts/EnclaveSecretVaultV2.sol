// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EnclaveSecretVaultV2: custody v2 (docs/security/secret-custody-v2.md; the interfaces are
///        docs/security/secret-custody-v2-spec.md §1, the byte formats custody/v2/protocol.mjs).
///
/// WHAT LIVES HERE (all of it public; none of it decryptable by this contract, the relay, or any one custodian):
///   - COMMITTEES: one committee key Y per committee, held as Shamir shares by custodian MACHINES running in TEEs on the
///     hosts. Per epoch: the machines (their Enclave flag computed here, from the registry, never supplied), the threshold
///     t, the share count W and the Feldman commitments (whose constant term is always Y). Shares move only by a HANDOVER
///     that a threshold of the CURRENT seats approved; nobody else (not governance, not the relay, not Enclave alone once
///     n >= 3) can change a committee.
///   - SEATS (protocol.mjs seatLayout): all Enclave-owned machines are ONE seat; every other machine is its own seat.
///     n >= 3: weight 1 each, t = ceil(2n/3). n < 3: the Enclave seat is required, t = others + 1 and the Enclave seat
///     holds t shares. Share indices: the Enclave seat first (1..wE), then the others in list order.
///   - CODE SET per committee: the custodian measurements machines may run. Adding one needs approval weight >= t AND a
///     7-day public delay; removing one needs the same approval weight and takes effect at once.
///   - per deployment, a POLICY (pinned owner, rules, committee, pause, revisions) and the current BUNDLE
///     (R ‖ label proof ‖ nonce ‖ AES-GCM ciphertext, threshold ElGamal under the committee's Y). As v1.
///
/// AUTHORIZATION of policies and bundles is v1's: the ledger's beneficial owner of the deployment (a SessionVault-held
/// record answers to that vault's owner), pinned at the first write; EIP-712 for the gasless/passkey path (ERC-1271 for
/// a contract owner); claimPolicy destroys the bundle when the ledger names a new owner.
///
/// No owner, no admin, no proxy. No ETH. The only external calls are view reads of the book, the registry and the ledger.
interface IVaultV2Book { function addr(bytes32 key) external view returns (address); }
interface IVaultV2Ledger {
    // byte-for-byte the ledger's Deployment tuple (stable since schema 2; contracts/SessionVault.sol ISVLedger)
    struct Deployment {
        bytes32 id; address owner; string appRef; string ports; string configCid;
        uint16 gpuMilli; uint16 cpuMilli; uint32 appPort; bool isPublic; bool active; uint64 createdAt;
        uint256 rate; uint256 balance6; uint256 spent6;
        bytes32 runner; address runnerOperator; uint64 leaseUntil;
    }
    function get(bytes32 id) external view returns (Deployment memory);
}
interface IVaultV2Registry { function get(bytes32 id) external view; }   // decoded by hand: only the schema-4 prefix
interface IVaultV2HostOwnership {
    function registry() external view returns (address);
    function authority(bytes32 hostId) external view returns (address owner, address pendingOwner, uint64 revision, bytes32 policyHash);
}
interface IVaultV2Factory { function isVault(address v) external view returns (bool); }
interface IVaultV2Session { function owner() external view returns (address); }
interface IVaultV21271 { function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4); }

contract EnclaveSecretVaultV2 {
    bytes32 private constant BOOK_DEPLOYMENTS = "deployments";
    bytes32 private constant BOOK_SESSION_FACTORY = "sessionVaultFactory";
    uint256 public constant MAX_SEATS = 64;
    uint256 public constant MAX_MACHINES = 96;
    uint256 public constant MAX_ENDPOINT = 190;
    uint256 public constant MAX_CODESET = 64;          // genesis code set entries (a bound on the loop)
    uint256 public constant MAX_SEALED = 4096;         // one HPKE deal envelope (at most 64 indices x 36 bytes + overhead)
    uint256 public constant MAX_BUNDLE = 24576;
    uint256 public constant MIN_BUNDLE = 125;          // R 33 + proof 64 + nonce 12 + GCM tag 16
    uint256 public constant MAX_RULES = 4096;
    uint256 public constant POINT = 33;
    uint64 public constant CODE_DELAY = 7 days;
    uint64 public constant HANDOVER_TTL = 1 days;

    IVaultV2Book public immutable book;
    address public immutable enclaveOwner;
    IVaultV2HostOwnership public immutable hostOwnership;
    address public immutable hostRegistry;
    address public immutable deploymentLedger;
    address public immutable sessionVaultFactory;

    // ---------------------------------------------------------------- committees
    struct Machine {
        address identity;      // secp256k1 key generated in the custodian's TEE (signs everything below)
        bytes32 encKey;        // X25519 public key (HPKE recipient for deals; challenge identity)
        string  endpoint;      // https origin of the custodian's API, <= 190 bytes
        bytes32 chipId;        // sha256(SNP report CHIP_ID, 64 bytes)
        bytes32 registryId;    // the HOST's EnclaveRegistry id (keccak256(bytes(host endpoint)))
        bytes32 measurement;   // sha256(SNP launch measurement, 48 bytes)
    }
    struct Deal { bytes commitments; bytes[] sealedTo; }
    /// one epoch, current or pending (an epoch number is never reused: a replaced proposal's epoch is abandoned)
    struct Epoch {
        uint8 t;
        uint8 W;
        uint64 expires;        // pending only: when a newer proposal may replace it
        uint32 deals;
        uint32 acks;
        uint256 dealt;         // bitmap of dealer indices that posted
        uint256 acked;         // bitmap of machine positions that acked
        bytes32 commitHash;    // keccak256(newCommitments) every ack must name
        uint32[] dealers;
        Machine[] machines;
        bool[] enclave;
        bytes commitments;
        mapping(uint32 => Deal) dealOf;
    }
    struct Committee {
        bytes Y;
        uint32 epoch;          // current
        uint32 pending;        // pending toEpoch, 0 = none
        uint32 lastEpoch;      // the highest epoch number ever used (current or proposed)
        uint64 activatedAt;
    }
    mapping(bytes32 => Committee) private _committees;
    mapping(bytes32 => mapping(uint32 => Epoch)) private _epochs;
    mapping(bytes32 => mapping(bytes32 => uint64)) private _codeActiveAt;
    mapping(bytes32 => bool) private _usedCodeDigest;

    // ---------------------------------------------------------------- policies and bundles
    struct Policy {
        address owner;        // pinned at the first write (beneficial ledger owner)
        uint64 policyRev;     // +1 on EVERY owner change (rules, committee, pause, bundle, clear, claim)
        uint64 secretRev;     // +1 on every bundle put or clear
        bytes32 committeeId;
        bool paused;          // owner's emergency stop: custodians release nothing while set
        bytes rules;          // canonical JSON, enforced by custodians
    }
    struct Bundle { bytes32 committeeId; bytes data; }   // the CURRENT revision only; history is in events
    mapping(bytes32 => Policy) private _policies;
    mapping(bytes32 => Bundle) private _bundles;

    // ---------------------------------------------------------------- EIP-712
    bytes32 private constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant UPDATE_TYPEHASH = keccak256("Update(bytes32 id,uint64 expectPolicyRev,uint64 deadline,bytes32 contentHash)");
    bytes32 private constant CLAIM_TYPEHASH = keccak256("Claim(bytes32 id,uint64 expectPolicyRev,uint64 deadline)");

    // ---------------------------------------------------------------- events
    event CommitteeCreated(bytes32 indexed committeeId, address indexed identity, bytes Y);
    event HandoverProposed(bytes32 indexed committeeId, uint32 toEpoch, uint8 t, uint8 W, uint256 machines, uint64 expires);
    event DealPosted(bytes32 indexed committeeId, uint32 toEpoch, uint32 dealerIndex, address dealer);
    event HandoverAcked(bytes32 indexed committeeId, uint32 toEpoch, address machine, uint256 acks);
    event EpochActivated(bytes32 indexed committeeId, uint32 epoch);
    event CodeProposed(bytes32 indexed committeeId, bytes32 indexed measurement, uint64 activeAt);
    event CodeRemoved(bytes32 indexed committeeId, bytes32 indexed measurement);
    event PolicyUpdated(bytes32 indexed id, address indexed owner, uint64 policyRev, bytes32 committeeId, bool paused);
    event BundlePut(bytes32 indexed id, uint64 secretRev, bytes32 committeeId, uint256 bundleBytes);
    event BundleCleared(bytes32 indexed id, uint64 secretRev);
    event PolicyClaimed(bytes32 indexed id, address indexed previousOwner, address indexed newOwner, uint64 policyRev);

    error NotOwner();
    error StaleRevision(uint64 current, uint64 expected);
    error BadCommittee();
    error BadBundle();
    error BadRules();
    error Expired();
    error BadSignature();
    error NoLedger();
    error NoRegistry();
    error NothingToClaim();
    error BadMachine();       // shape, duplicate identity, duplicate non-Enclave chip
    error BadHost();          // registry entry missing/inactive, or the host signature is not its operator's
    error NotEnclave();       // genesis by a machine that is not Enclave-owned
    error BadSeats();         // > 64 seats, > 96 machines, or < 3 seats without the Enclave seat
    error BadCode();          // a measurement not (or not yet, or no longer) in the code set
    error BadDealers();
    error Pending();          // a pending handover has not expired
    error NoPending();
    error NotMachine();
    error Weight(uint256 got, uint256 need);
    error BadDeal();
    error BadAck();

    constructor(address book_, address enclaveOwner_, address hostOwnership_) {
        if (book_ == address(0) || enclaveOwner_ == address(0)) revert();
        if (hostOwnership_.code.length == 0) revert BadHost();
        hostOwnership = IVaultV2HostOwnership(hostOwnership_);
        address registry_ = IVaultV2HostOwnership(hostOwnership_).registry();
        if (registry_.code.length == 0) revert NoRegistry();
        hostRegistry = registry_;
        book = IVaultV2Book(book_);
        address ledger_ = IVaultV2Book(book_).addr(BOOK_DEPLOYMENTS);
        if (ledger_.code.length == 0) revert NoLedger();
        deploymentLedger = ledger_;
        address factory_ = IVaultV2Book(book_).addr(BOOK_SESSION_FACTORY);
        if (factory_ != address(0) && factory_.code.length == 0) revert();
        sessionVaultFactory = factory_;
        enclaveOwner = enclaveOwner_;
    }

    // ================================================================= signatures
    /// EIP-2: the low-s half only (s <= secp256k1 n / 2), so a signature has exactly one valid form
    function _lowS(bytes32 s) private pure returns (bool) {
        return uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    }
    /// EIP-191 personal_sign over a 32-byte digest, 65 bytes, low-s, v in {27, 28}. address(0) on any malformed input.
    function _recover(bytes32 digest, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (!_lowS(s) || (v != 27 && v != 28)) return address(0);
        return ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)), v, r, s);
    }
    function _checkSig(address signer, bytes32 digest, bytes calldata sig) private pure {
        address got = _recover(digest, sig);
        if (got == address(0) || got != signer) revert BadSignature();
    }

    // ================================================================= digests (spec §1.2)
    function machineHash(Machine calldata m) public pure returns (bytes32) {
        return keccak256(abi.encode(m.identity, m.encKey, keccak256(bytes(m.endpoint)), m.chipId, m.registryId, m.measurement));
    }
    function _hostDigest(bytes32 mh) private view returns (bytes32) {
        return keccak256(abi.encode("enclave-custody-v2 host", block.chainid, address(this), mh));
    }

    // ================================================================= machines and seats
    /// The ownership contract pins the registry. A mutable address-book entry
    /// cannot reclassify a host. Only operator and active from its stable prefix
    /// are read here; payout declarations never confer custody authority.
    function _hostOf(bytes32 registryId) private view returns (address operator, bool active) {
        (bool ok, bytes memory ret) = hostRegistry.staticcall(abi.encodeCall(IVaultV2Registry.get, (registryId)));
        if (!ok || ret.length < 32) revert BadHost();
        uint256 base;
        assembly ("memory-safe") { base := mload(add(ret, 32)) }
        if (base > ret.length || ret.length - base < 7 * 32) revert BadHost();
        uint256 wOp; uint256 wActive;
        assembly ("memory-safe") {
            let p := add(add(ret, 32), base)
            wOp := mload(add(p, 96))
            wActive := mload(add(p, 192))
        }
        if (wOp >> 160 != 0 || wActive > 1) revert BadHost();
        return (address(uint160(wOp)), wActive == 1);
    }

    /// shape checks, the host binding, and the computed Enclave flag (spec §1.1)
    function _admit(Machine calldata m, bytes calldata hostSig) private view returns (bool enclave) {
        uint256 len = bytes(m.endpoint).length;
        if (m.identity == address(0) || m.encKey == bytes32(0) || m.chipId == bytes32(0) || len == 0 || len > MAX_ENDPOINT) revert BadMachine();
        (address operator, bool active) = _hostOf(m.registryId);
        if (!active || operator == address(0)) revert BadHost();
        address got = _recover(_hostDigest(machineHash(m)), hostSig);
        if (got == address(0) || got != operator) revert BadHost();
        (address owner,,,) = hostOwnership.authority(m.registryId);
        if (owner == address(0)) revert BadHost();
        return owner == enclaveOwner;
    }

    /// protocol.mjs seatLayout: -> (seats n, threshold t, share count W, Enclave seat weight wE (0 = no Enclave seat))
    function _layout(bool[] memory enc) private pure returns (uint256 n, uint256 t, uint256 W, uint256 wE) {
        uint256 others;
        bool hasE;
        for (uint256 i = 0; i < enc.length; i++) { if (enc[i]) hasE = true; else others++; }
        n = others + (hasE ? 1 : 0);
        if (n == 0 || n > MAX_SEATS || enc.length > MAX_MACHINES) revert BadSeats();
        if (n >= 3) { t = (2 * n + 2) / 3; wE = hasE ? 1 : 0; }
        else { if (!hasE) revert BadSeats(); t = others + 1; wE = t; }
        W = wE + others;
    }
    /// the share indices machine `i` holds: [first, first + count)
    function _indicesOf(bool[] memory enc, uint256 i, uint256 wE) private pure returns (uint256 first, uint256 count) {
        if (enc[i]) return (1, wE);
        first = wE + 1;
        for (uint256 j = 0; j < i; j++) if (!enc[j]) first++;
        return (first, 1);
    }
    function _position(Epoch storage e, address who) private view returns (uint256) {
        uint256 n = e.machines.length;
        for (uint256 i = 0; i < n; i++) if (e.machines[i].identity == who) return i;
        revert NotMachine();
    }

    /// approval weight: the distinct seats of the CURRENT epoch with at least one signing machine (spec §1.2). The Enclave
    /// seat counts once (bit 0), however many Enclave machines sign; every other machine i is seat bit i + 1.
    function _approve(bytes32 cid, bytes32 digest, address[] calldata approvers, bytes[] calldata approvals) private view {
        Committee storage c = _committees[cid];
        Epoch storage e = _epochs[cid][c.epoch];
        if (approvers.length != approvals.length || approvers.length > MAX_MACHINES) revert BadSignature();
        bool[] memory enc = e.enclave;
        (, uint256 t,, uint256 wE) = _layout(enc);
        uint256 seats;
        for (uint256 k = 0; k < approvers.length; k++) {
            _checkSig(approvers[k], digest, approvals[k]);
            uint256 i = _position(e, approvers[k]);
            seats |= enc[i] ? uint256(1) : (uint256(1) << (i + 1));
        }
        uint256 w = (seats & 1) != 0 ? wE : 0;
        for (uint256 x = seats >> 1; x != 0; x &= x - 1) w++;
        if (w < t) revert Weight(w, t);
    }

    // ================================================================= committees (spec §1.3)
    function createCommittee(bytes32 salt, Machine calldata m, bytes calldata Y, bytes32[] calldata codeSet,
                             bytes calldata identitySig, bytes calldata hostSig) external returns (bytes32 committeeId) {
        if (Y.length != POINT || (Y[0] != 0x02 && Y[0] != 0x03)) revert BadCommittee();
        committeeId = keccak256(abi.encode(block.chainid, address(this), salt, keccak256(Y)));
        Committee storage c = _committees[committeeId];
        if (c.epoch != 0) revert BadCommittee();
        if (codeSet.length == 0 || codeSet.length > MAX_CODESET) revert BadCode();
        bool inSet;
        for (uint256 i = 0; i < codeSet.length; i++) {
            if (codeSet[i] == bytes32(0)) revert BadCode();
            if (codeSet[i] == m.measurement) inSet = true;
        }
        if (!inSet) revert BadCode();
        bytes32 mh = machineHash(m);
        if (!_admit(m, hostSig)) revert NotEnclave();
        _checkSig(m.identity, keccak256(abi.encode("enclave-custody-v2 genesis", block.chainid, address(this), committeeId,
                  keccak256(Y), mh, keccak256(abi.encode(codeSet)))), identitySig);

        c.Y = Y;
        c.epoch = 1;
        c.lastEpoch = 1;
        c.activatedAt = uint64(block.timestamp);
        Epoch storage e = _epochs[committeeId][1];
        e.t = 1;
        e.W = 1;
        e.machines.push(m);
        e.enclave.push(true);
        e.commitments = Y;
        for (uint256 i = 0; i < codeSet.length; i++) _codeActiveAt[committeeId][codeSet[i]] = uint64(block.timestamp);
        emit CommitteeCreated(committeeId, m.identity, Y);
        emit EpochActivated(committeeId, 1);
    }

    /// An independent committee starts at its full threshold, without an Enclave
    /// founder. Each measured member must verify distributed key generation and
    /// persist its own share before signing this exact roster/code/commitment set.
    /// Anyone may submit the signatures; no caller gains authority over the key.
    function createIndependentCommittee(bytes32 salt, Machine[] calldata machines, bytes calldata commitments,
                                        bytes32[] calldata codeSet, bytes[] calldata identitySigs,
                                        bytes[] calldata hostSigs) external returns (bytes32 cid) {
        uint256 n = machines.length;
        if (n < 3 || n > MAX_SEATS || identitySigs.length != n || hostSigs.length != n) revert BadSeats();
        uint256 t = (2 * n + 2) / 3;
        if (commitments.length != t * POINT) revert BadCommittee();
        for (uint256 i = 0; i < t; i++) {
            if (commitments[i * POINT] != 0x02 && commitments[i * POINT] != 0x03) revert BadCommittee();
        }
        if (codeSet.length == 0 || codeSet.length > MAX_CODESET) revert BadCode();
        for (uint256 i = 0; i < codeSet.length; i++) if (codeSet[i] == bytes32(0)) revert BadCode();
        bytes32[] memory hashes = new bytes32[](n);
        address[] memory owners = new address[](n);
        for (uint256 i = 0; i < n; i++) {
            Machine calldata m = machines[i];
            if (_admit(m, hostSigs[i])) revert BadSeats();
            (owners[i],,,) = hostOwnership.authority(m.registryId);
            bool admittedCode;
            for (uint256 j = 0; j < codeSet.length; j++) if (m.measurement == codeSet[j]) admittedCode = true;
            if (!admittedCode) revert BadCode();
            for (uint256 j = 0; j < i; j++) {
                if (machines[j].identity == m.identity || machines[j].encKey == m.encKey ||
                    machines[j].chipId == m.chipId || machines[j].registryId == m.registryId ||
                    owners[j] == owners[i]) revert BadMachine();
            }
            hashes[i] = machineHash(m);
        }
        bytes memory Y = commitments[0:POINT];
        cid = keccak256(abi.encode(block.chainid, address(this), salt, keccak256(Y)));
        Committee storage c = _committees[cid];
        if (c.epoch != 0) revert BadCommittee();
        bytes32 digest = keccak256(abi.encode("enclave-custody-v2 independent genesis", block.chainid,
            address(this), cid, keccak256(commitments), keccak256(abi.encode(hashes)), keccak256(abi.encode(codeSet))));
        for (uint256 i = 0; i < n; i++) _checkSig(machines[i].identity, digest, identitySigs[i]);
        c.Y = Y;
        c.epoch = 1;
        c.lastEpoch = 1;
        c.activatedAt = uint64(block.timestamp);
        Epoch storage e = _epochs[cid][1];
        e.t = uint8(t);
        e.W = uint8(n);
        e.commitments = commitments;
        for (uint256 i = 0; i < n; i++) { e.machines.push(machines[i]); e.enclave.push(false); }
        for (uint256 i = 0; i < codeSet.length; i++) _codeActiveAt[cid][codeSet[i]] = uint64(block.timestamp);
        emit CommitteeCreated(cid, machines[0].identity, Y);
        emit EpochActivated(cid, 1);
    }

    function proposeHandover(bytes32 cid, Machine[] calldata next, bytes[] calldata hostSigs, uint32[] calldata dealerIndices,
                             address[] calldata approvers, bytes[] calldata approvals) external {
        Committee storage c = _committees[cid];
        if (c.epoch == 0) revert BadCommittee();
        if (c.pending != 0 && _epochs[cid][c.pending].expires > block.timestamp) revert Pending();
        uint256 n = next.length;
        if (n == 0 || n > MAX_MACHINES || hostSigs.length != n) revert BadSeats();

        // the new machines: shape, host binding, Enclave flag, code, uniqueness
        bool[] memory enc = new bool[](n);
        bytes32[] memory hashes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            Machine calldata m = next[i];
            uint64 at = _codeActiveAt[cid][m.measurement];
            if (at == 0 || at > block.timestamp) revert BadCode();
            enc[i] = _admit(m, hostSigs[i]);
            hashes[i] = machineHash(m);
            for (uint256 j = 0; j < i; j++) {
                if (next[j].identity == m.identity) revert BadMachine();
                if (!enc[i] && !enc[j] && next[j].chipId == m.chipId) revert BadMachine();
            }
        }
        (, uint256 tNew, uint256 wNew,) = _layout(enc);

        // the dealers: exactly t_old distinct indices in 1..W_old
        Epoch storage cur = _epochs[cid][c.epoch];
        uint256 tOld = cur.t;
        if (dealerIndices.length != tOld) revert BadDealers();
        uint256 seen;
        for (uint256 i = 0; i < dealerIndices.length; i++) {
            uint256 k = dealerIndices[i];
            if (k == 0 || k > cur.W || seen & (uint256(1) << k) != 0) revert BadDealers();
            seen |= uint256(1) << k;
        }

        _approve(cid, keccak256(abi.encode("enclave-custody-v2 handover", block.chainid, address(this), cid, c.epoch,
                 keccak256(abi.encode(hashes)), keccak256(abi.encode(dealerIndices)))), approvers, approvals);

        uint32 toEpoch = c.lastEpoch + 1;
        c.lastEpoch = toEpoch;
        c.pending = toEpoch;
        Epoch storage p = _epochs[cid][toEpoch];
        p.t = uint8(tNew);
        p.W = uint8(wNew);
        uint64 expires = uint64(block.timestamp) + HANDOVER_TTL;
        p.expires = expires;
        p.dealers = dealerIndices;
        for (uint256 i = 0; i < n; i++) { p.machines.push(next[i]); p.enclave.push(enc[i]); }
        emit HandoverProposed(cid, toEpoch, uint8(tNew), uint8(wNew), n, expires);
    }

    function postDeal(bytes32 cid, uint32 toEpoch, uint32 dealerIndex, bytes calldata dealCommitments, bytes[] calldata sealedTo,
                      address dealer, bytes calldata sig) external {
        Committee storage c = _committees[cid];
        if (toEpoch == 0 || c.pending != toEpoch) revert NoPending();
        Epoch storage p = _epochs[cid][toEpoch];
        // the index is one of the proposal's dealers, not yet dealt
        bool listed;
        for (uint256 i = 0; i < p.dealers.length; i++) if (p.dealers[i] == dealerIndex) listed = true;
        if (!listed || p.dealt & (uint256(1) << dealerIndex) != 0) revert BadDealers();
        // the dealer is a current machine holding that index
        Epoch storage cur = _epochs[cid][c.epoch];
        bool[] memory enc = cur.enclave;
        (,,, uint256 wE) = _layout(enc);
        (uint256 first, uint256 count) = _indicesOf(enc, _position(cur, dealer), wE);
        if (dealerIndex < first || dealerIndex >= first + count) revert BadDealers();
        // shape: t_new commitments, one envelope per new machine
        uint256 n = p.machines.length;
        if (dealCommitments.length != uint256(p.t) * POINT || sealedTo.length != n) revert BadDeal();
        for (uint256 i = 0; i < n; i++) if (sealedTo[i].length == 0 || sealedTo[i].length > MAX_SEALED) revert BadDeal();
        _checkSig(dealer, keccak256(abi.encode("enclave-custody-v2 deal", block.chainid, address(this), cid, toEpoch, dealerIndex,
                  keccak256(dealCommitments), keccak256(abi.encode(sealedTo)))), sig);

        p.dealt |= uint256(1) << dealerIndex;
        p.deals += 1;
        Deal storage d = p.dealOf[dealerIndex];
        d.commitments = dealCommitments;
        for (uint256 i = 0; i < n; i++) d.sealedTo.push(sealedTo[i]);
        emit DealPosted(cid, toEpoch, dealerIndex, dealer);
    }

    function ackHandover(bytes32 cid, uint32 toEpoch, bytes calldata newCommitments, address machine, bytes calldata sig) external {
        Committee storage c = _committees[cid];
        if (toEpoch == 0 || c.pending != toEpoch) revert NoPending();
        Epoch storage p = _epochs[cid][toEpoch];
        if (p.deals != p.dealers.length) revert BadAck();                    // every dealer's deal is on chain first
        uint256 i = _position(p, machine);
        if (p.acked & (uint256(1) << i) != 0) revert BadAck();
        if (newCommitments.length != uint256(p.t) * POINT || keccak256(newCommitments[0:POINT]) != keccak256(c.Y)) revert BadAck();
        bytes32 h = keccak256(newCommitments);
        if (p.acks != 0 && h != p.commitHash) revert BadAck();
        _checkSig(machine, keccak256(abi.encode("enclave-custody-v2 ack", block.chainid, address(this), cid, toEpoch, h)), sig);

        if (p.acks == 0) { p.commitHash = h; p.commitments = newCommitments; }
        p.acked |= uint256(1) << i;
        uint32 acks = p.acks + 1;
        p.acks = acks;
        emit HandoverAcked(cid, toEpoch, machine, acks);
        uint256 n = p.machines.length;
        if (acks == n) {
            // every new machine still runs admitted code: a measurement removed while the handover was pending stops it
            for (uint256 j = 0; j < n; j++) {
                uint64 at = _codeActiveAt[cid][p.machines[j].measurement];
                if (at == 0 || at > block.timestamp) revert BadCode();
            }
            c.epoch = toEpoch;
            c.pending = 0;
            c.activatedAt = uint64(block.timestamp);
            p.expires = 0;
            emit EpochActivated(cid, toEpoch);
        }
    }

    function _codeDigest(bytes32 cid, bytes32 measurement, bool add) private returns (bytes32 d) {
        Committee storage c = _committees[cid];
        if (c.epoch == 0) revert BadCommittee();
        d = keccak256(abi.encode("enclave-custody-v2 code", block.chainid, address(this), cid, c.epoch, measurement, add));
        // one use per digest: an add's approvals cannot be replayed after a remove in the same epoch (or the reverse)
        if (_usedCodeDigest[d]) revert BadSignature();
        _usedCodeDigest[d] = true;
    }
    function proposeCode(bytes32 cid, bytes32 measurement, address[] calldata approvers, bytes[] calldata approvals) external {
        bytes32 d = _codeDigest(cid, measurement, true);
        if (measurement == bytes32(0) || _codeActiveAt[cid][measurement] != 0) revert BadCode();
        _approve(cid, d, approvers, approvals);
        uint64 at = uint64(block.timestamp) + CODE_DELAY;
        _codeActiveAt[cid][measurement] = at;
        emit CodeProposed(cid, measurement, at);
    }
    function removeCode(bytes32 cid, bytes32 measurement, address[] calldata approvers, bytes[] calldata approvals) external {
        bytes32 d = _codeDigest(cid, measurement, false);
        if (_codeActiveAt[cid][measurement] == 0) revert BadCode();
        _approve(cid, d, approvers, approvals);
        delete _codeActiveAt[cid][measurement];
        emit CodeRemoved(cid, measurement);
    }

    // ---------------------------------------------------------------- committee views
    function committeeOf(bytes32 cid) external view returns (bytes memory Y, uint32 epoch, uint8 t, uint8 W, uint64 activatedAt) {
        Committee storage c = _committees[cid];
        Epoch storage e = _epochs[cid][c.epoch];
        return (c.Y, c.epoch, e.t, e.W, c.activatedAt);
    }
    function machinesOf(bytes32 cid, uint32 epoch) external view returns (Machine[] memory machines, bool[] memory enclave) {
        Epoch storage e = _epochs[cid][epoch];
        return (e.machines, e.enclave);
    }
    function commitmentsOf(bytes32 cid, uint32 epoch) external view returns (bytes memory) { return _epochs[cid][epoch].commitments; }
    function pendingOf(bytes32 cid) external view returns (uint32 toEpoch, Machine[] memory next, bool[] memory enclave, uint8 t,
                                                           uint8 W, uint32[] memory dealers, uint64 expires) {
        toEpoch = _committees[cid].pending;
        if (toEpoch == 0) return (0, next, enclave, 0, 0, dealers, 0);
        Epoch storage p = _epochs[cid][toEpoch];
        return (toEpoch, p.machines, p.enclave, p.t, p.W, p.dealers, p.expires);
    }
    function dealOf(bytes32 cid, uint32 toEpoch, uint32 dealerIndex) external view returns (bytes memory dealCommitments, bytes[] memory sealedTo) {
        Deal storage d = _epochs[cid][toEpoch].dealOf[dealerIndex];
        return (d.commitments, d.sealedTo);
    }
    function ackCount(bytes32 cid, uint32 toEpoch) external view returns (uint256) { return _epochs[cid][toEpoch].acks; }
    function codeActiveAt(bytes32 cid, bytes32 measurement) external view returns (uint64) { return _codeActiveAt[cid][measurement]; }

    // ================================================================= ownership (as v1)
    function _ledger() private view returns (IVaultV2Ledger) {
        return IVaultV2Ledger(deploymentLedger);
    }
    /// the ledger's owner of `id`, or, for a SessionVault-held record, that vault's owner (who alone may set secrets: a
    /// session key never can). address(0) for no such deployment.
    function beneficialOwnerOf(bytes32 id) public view returns (address o) {
        o = _ledger().get(id).owner;
        if (o == address(0) || o.code.length == 0) return o;
        address f = sessionVaultFactory;
        if (f != address(0)) {
            try IVaultV2Factory(f).isVault(o) returns (bool v) {
                if (v) return IVaultV2Session(o).owner();
            } catch {}
        }
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256("EnclaveSecretVaultV2"), keccak256("1"), block.chainid, address(this)));
    }
    /// an EOA by ecrecover (raw EIP-712 digest, low-s), a contract owner (the passkey credit vault) by ERC-1271
    function _isValidOwnerSig(address signer, bytes32 digest, bytes calldata sig) private view returns (bool) {
        if (signer == address(0)) return false;
        if (signer.code.length > 0) {
            try IVaultV21271(signer).isValidSignature(digest, sig) returns (bytes4 m) { return m == 0x1626ba7e; } catch { return false; }
        }
        if (sig.length != 65) return false;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (v < 27) v += 27;
        if (!_lowS(s) || (v != 27 && v != 28)) return false;
        address got = ecrecover(digest, v, r, s);
        return got != address(0) && got == signer;
    }

    // ================================================================= owner updates (spec §1.4)
    struct Update {
        uint64 expectPolicyRev;   // the policy revision this update was built against (also its replay guard)
        bool setPolicy;           // replace committeeId, paused and rules
        bytes32 committeeId;
        bool paused;
        bytes rules;
        bool setBundle;           // a new bundle for secretRev + 1, under the policy's committee
        bytes bundle;             // R ‖ proof ‖ nonce ‖ ct
        bool clear;               // destroy the bundle (secretRev + 1, nothing stored)
    }

    function contentHash(Update calldata u) public pure returns (bytes32) { return keccak256(abi.encode(u)); }
    function updateDigest(bytes32 id, Update calldata u, uint64 deadline) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(),
            keccak256(abi.encode(UPDATE_TYPEHASH, id, u.expectPolicyRev, deadline, contentHash(u)))));
    }

    function update(bytes32 id, Update calldata u) external {
        address owner = _ownerFor(id);
        if (msg.sender != owner) revert NotOwner();
        _apply(id, owner, u);
    }

    /// gasless and passkey path: anyone submits; the pinned owner (or, at the first write, the ledger's owner) signed it
    function updateBySig(bytes32 id, Update calldata u, uint64 deadline, bytes calldata sig) external {
        if (block.timestamp > deadline) revert Expired();
        address owner = _ownerFor(id);
        if (!_isValidOwnerSig(owner, updateDigest(id, u, deadline), sig)) revert BadSignature();
        _apply(id, owner, u);
    }

    function _ownerFor(bytes32 id) private view returns (address) {
        Policy storage p = _policies[id];
        if (p.policyRev != 0) return p.owner;
        address o = beneficialOwnerOf(id);
        if (o == address(0)) revert NotOwner();
        return o;
    }

    function _apply(bytes32 id, address owner, Update calldata u) private {
        Policy storage p = _policies[id];
        if (u.expectPolicyRev != p.policyRev) revert StaleRevision(p.policyRev, u.expectPolicyRev);
        if (p.policyRev == 0) {
            // first write: it must establish a policy (a committee and rules) for anything to be releasable
            if (!u.setPolicy) revert BadRules();
            p.owner = owner;
        } else if (beneficialOwnerOf(id) != p.owner) {
            // the ledger moved the deployment: only claimPolicy (which destroys the bundle) may follow
            revert NotOwner();
        }
        if (u.setBundle && u.clear) revert BadBundle();
        if (u.setPolicy) {
            if (_committees[u.committeeId].epoch == 0) revert BadCommittee();
            if (u.rules.length == 0 || u.rules.length > MAX_RULES) revert BadRules();
            // a bundle is encrypted to ONE committee's key (and its label names it): changing the committee with a bundle
            // in place needs a fresh bundle (or a clear)
            if (u.committeeId != p.committeeId && _bundles[id].data.length != 0 && !u.setBundle && !u.clear) revert BadCommittee();
            p.committeeId = u.committeeId;
            p.paused = u.paused;
            p.rules = u.rules;
        }
        if (u.setBundle) {
            bytes32 cid = p.committeeId;
            if (_committees[cid].epoch == 0) revert BadCommittee();
            if (u.bundle.length < MIN_BUNDLE || u.bundle.length > MAX_BUNDLE) revert BadBundle();
            uint64 rev = p.secretRev + 1;
            p.secretRev = rev;
            _bundles[id] = Bundle(cid, u.bundle);
            emit BundlePut(id, rev, cid, u.bundle.length);
        }
        if (u.clear) {
            p.secretRev += 1;
            delete _bundles[id];
            emit BundleCleared(id, p.secretRev);
        }
        p.policyRev += 1;
        emit PolicyUpdated(id, p.owner, p.policyRev, p.committeeId, p.paused);
    }

    /// the ledger's current owner takes over a policy the ledger no longer gives the pinned owner. The bundle is destroyed:
    /// the new owner starts with no secrets, and the previous owner's never reach code the new owner controls.
    function claimPolicy(bytes32 id) external { _claim(id, msg.sender); }
    function claimPolicyBySig(bytes32 id, uint64 expectPolicyRev, uint64 deadline, bytes calldata sig) external {
        if (block.timestamp > deadline) revert Expired();
        Policy storage p = _policies[id];
        if (expectPolicyRev != p.policyRev) revert StaleRevision(p.policyRev, expectPolicyRev);
        address o = beneficialOwnerOf(id);
        bytes32 d = keccak256(abi.encodePacked("\x19\x01", domainSeparator(), keccak256(abi.encode(CLAIM_TYPEHASH, id, expectPolicyRev, deadline))));
        if (!_isValidOwnerSig(o, d, sig)) revert BadSignature();
        _claim(id, o);
    }
    function _claim(bytes32 id, address claimant) private {
        Policy storage p = _policies[id];
        address o = beneficialOwnerOf(id);
        if (p.policyRev == 0 || o == p.owner) revert NothingToClaim();
        if (claimant != o) revert NotOwner();
        address prev = p.owner;
        p.owner = o;
        p.paused = true;               // nothing is releasable until the new owner sets its own policy
        p.secretRev += 1;
        p.policyRev += 1;
        delete _bundles[id];
        emit BundleCleared(id, p.secretRev);
        emit PolicyClaimed(id, prev, o, p.policyRev);
        emit PolicyUpdated(id, o, p.policyRev, p.committeeId, true);
    }

    function policyOf(bytes32 id) external view returns (address owner, uint64 policyRev, uint64 secretRev, bytes32 committeeId, bool paused, bytes memory rules) {
        Policy storage p = _policies[id];
        return (p.owner, p.policyRev, p.secretRev, p.committeeId, p.paused, p.rules);
    }
    function bundleOf(bytes32 id) external view returns (bytes32 committeeId, uint64 secretRev, bytes memory bundle) {
        Bundle storage b = _bundles[id];
        return (b.committeeId, _policies[id].secretRev, b.data);
    }
}
