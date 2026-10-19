// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { Test } from "forge-std/Test.sol";
import { EnclaveSecretVaultV2, IVaultV2Ledger } from "../../EnclaveSecretVaultV2.sol";
import { EnclaveHostOwnership } from "../../EnclaveHostOwnership.sol";
import { EnclaveRegistry } from "../../EnclaveRegistry.sol";

contract V2Book {
    mapping(bytes32 => address) public addr;
    function set(bytes32 k, address v) external { addr[k] = v; }
}
contract V2Ledger {
    mapping(bytes32 => IVaultV2Ledger.Deployment) private d;
    function setOwner(bytes32 id, address o) external { d[id].id = id; d[id].owner = o; }
    function get(bytes32 id) external view returns (IVaultV2Ledger.Deployment memory) { return d[id]; }
}
contract V2Factory {
    mapping(address => bool) public isVault;
    function add(address v) external { isVault[v] = true; }
}
contract V2SessionVault {
    address public owner;
    constructor(address o) { owner = o; }
}
contract V21271 {
    address public signer;
    constructor(address s) { signer = s; }
    function isValidSignature(bytes32 h, bytes calldata sig) external view returns (bytes4) {
        if (sig.length != 65) return 0xffffffff;
        bytes32 r = bytes32(sig[0:32]); bytes32 s = bytes32(sig[32:64]); uint8 v = uint8(sig[64]);
        return ecrecover(h, v, r, s) == signer ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

/// The REAL EnclaveRegistry (schema 5: caps and region appended after payoutWallet) stands behind the book, so the vault's
/// schema-4 prefix decode is exercised against the live struct shape.
contract EnclaveSecretVaultV2Test is Test {
    EnclaveSecretVaultV2 vault;
    V2Book book;
    EnclaveRegistry registry;
    EnclaveHostOwnership ownership;
    V2Ledger ledger;
    V2Factory factory;
    address enclaveOwner = makeAddr("enclaveOwner");
    address otherWallet = makeAddr("someHostsWallet");
    address stranger = makeAddr("stranger");
    bytes32 constant M = keccak256("custodian-measurement-1");
    bytes32 constant M2 = keccak256("custodian-measurement-2");
    bytes Y;

    mapping(address => uint256) idKey;      // machine identity -> its key
    mapping(bytes32 => uint256) opKey;      // registry id -> host operator key

    uint256 ownerKey = 0xA11CE;
    address owner;
    bytes32 constant D = keccak256("deployment-1");

    function setUp() public {
        vm.warp(1_800_000_000);
        book = new V2Book();
        registry = new EnclaveRegistry();
        ledger = new V2Ledger();
        factory = new V2Factory();
        book.set("registry", address(registry));
        book.set("deployments", address(ledger));
        book.set("sessionVaultFactory", address(factory));
        ownership = new EnclaveHostOwnership(address(registry));
        vault = new EnclaveSecretVaultV2(address(book), enclaveOwner, address(ownership));
        Y = abi.encodePacked(bytes1(0x02), keccak256("committee-key"));
        owner = vm.addr(ownerKey);
        ledger.setOwner(D, owner);
    }

    // ================================================================= helpers
    function _psign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)));
        return abi.encodePacked(r, s, v);
    }
    function _mh(EnclaveSecretVaultV2.Machine memory m) internal pure returns (bytes32) {
        return keccak256(abi.encode(m.identity, m.encKey, keccak256(bytes(m.endpoint)), m.chipId, m.registryId, m.measurement));
    }
    function _hostDigest(EnclaveSecretVaultV2.Machine memory m) internal view returns (bytes32) {
        return keccak256(abi.encode("enclave-custody-v2 host", block.chainid, address(vault), _mh(m)));
    }
    function _hostSig(EnclaveSecretVaultV2.Machine memory m) internal view returns (bytes memory) {
        return _psign(opKey[m.registryId], _hostDigest(m));
    }

    /// a host registered by its own operator; `payout` is what its payout wallet declares (address(0) = none)
    function _host(uint256 seed, address payout) internal returns (bytes32 rid) {
        uint256 k = 0x2000 + seed;
        vm.prank(vm.addr(k));
        rid = registry.register(string.concat("https://host", vm.toString(seed), ".example"), "EnclaveHost/enclave", bytes32(0), 1, 0, address(0));
        opKey[rid] = k;
        if (payout != address(0)) {
            vm.prank(payout); registry.setPayoutWallet(rid);
            (address accepted,,,) = ownership.authority(rid);
            if (accepted == address(0)) {
                vm.prank(vm.addr(k)); ownership.proposeOwner(rid,payout);
                vm.prank(payout); ownership.acceptOwner(rid);
            }
        }
    }
    /// a custodian machine on its own host; Enclave-owned iff `enclave`
    function _machine(uint256 seed, bool enclave) internal returns (EnclaveSecretVaultV2.Machine memory m) {
        bytes32 rid = _host(seed, enclave ? enclaveOwner : otherWallet);
        m = _machineOn(seed, rid);
    }
    function _machineOn(uint256 seed, bytes32 rid) internal returns (EnclaveSecretVaultV2.Machine memory m) {
        uint256 k = 0x1000 + seed;
        m = EnclaveSecretVaultV2.Machine(vm.addr(k), keccak256(abi.encode("enc", seed)), string.concat("https://custodian", vm.toString(seed), ".example"),
                                         keccak256(abi.encode("chip", seed)), rid, M);
        idKey[m.identity] = k;
    }

    function _codeSet() internal pure returns (bytes32[] memory cs) { cs = new bytes32[](1); cs[0] = M; }
    function _independentMachines() internal returns (EnclaveSecretVaultV2.Machine[] memory ms) {
        ms = new EnclaveSecretVaultV2.Machine[](3);
        for (uint256 i; i < 3; i++) ms[i] = _machineOn(800+i, _host(800+i, vm.addr(900+i)));
    }
    function _independentSigs(EnclaveSecretVaultV2.Machine[] memory ms, bytes memory cs, bytes32[] memory codes)
        internal view returns (bytes[] memory sigs) {
        bytes32[] memory hashes = new bytes32[](ms.length);
        for (uint256 i; i < ms.length; i++) hashes[i] = _mh(ms[i]);
        bytes32 digest = keccak256(abi.encode("enclave-custody-v2 independent genesis", block.chainid,
            address(vault), _cid("independent"), keccak256(cs), keccak256(abi.encode(hashes)), keccak256(abi.encode(codes))));
        sigs = new bytes[](ms.length);
        for (uint256 i; i < ms.length; i++) sigs[i] = _psign(idKey[ms[i].identity], digest);
    }
    function test_independentGenesisAndCodeQuorumWithoutEnclave() public {
        EnclaveSecretVaultV2.Machine[] memory ms = _independentMachines();
        bytes memory cs = bytes.concat(Y,Y);
        bytes[] memory sigs = _independentSigs(ms,cs,_codeSet());
        // Delete mutable discovery before submission; the vault keeps its pins.
        book.set("registry", address(0)); book.set("deployments", address(0));
        vm.prank(stranger);
        bytes32 cid = vault.createIndependentCommittee("independent",ms,cs,_codeSet(),sigs,_hostSigs(ms));
        (bytes memory key, uint32 epoch, uint8 t, uint8 W,) = vault.committeeOf(cid);
        assertEq(key,Y); assertEq(epoch,1); assertEq(t,2); assertEq(W,3);
        (,bool[] memory enc) = vault.machinesOf(cid,1);
        assertFalse(enc[0]); assertFalse(enc[1]); assertFalse(enc[2]);
        address[] memory ap = new address[](2); ap[0]=ms[0].identity; ap[1]=ms[1].identity;
        vault.proposeCode(cid,M2,ap,_codeSigs(cid,M2,true,ap));
        assertGt(vault.codeActiveAt(cid,M2), block.timestamp);
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.createIndependentCommittee("independent",ms,cs,_codeSet(),sigs,_hostSigs(ms));
    }
    function test_independentGenesisRejectsRosterCodeAndCommitmentSubstitution() public {
        EnclaveSecretVaultV2.Machine[] memory ms = _independentMachines();
        bytes memory cs = bytes.concat(Y,Y);
        bytes[] memory sigs = _independentSigs(ms,cs,_codeSet());
        bytes[] memory hosts = _hostSigs(ms);
        bytes memory changed = bytes.concat(Y, abi.encodePacked(bytes1(0x03), bytes32(uint256(99))));
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.createIndependentCommittee("independent",ms,changed,_codeSet(),sigs,hosts);
        bytes32[] memory codes = new bytes32[](2); codes[0]=M; codes[1]=M2;
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.createIndependentCommittee("independent",ms,cs,codes,sigs,hosts);
        sigs[2]=sigs[1];
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.createIndependentCommittee("independent",ms,cs,_codeSet(),sigs,hosts);
    }
    function test_independentGenesisRequiresDistinctOwnersAndChips() public {
        EnclaveSecretVaultV2.Machine[] memory ms = _independentMachines();
        bytes memory cs = bytes.concat(Y,Y);
        ms[1].chipId=ms[0].chipId;
        bytes[] memory hosts = _hostSigs(ms);
        bytes[] memory sigs = _independentSigs(ms,cs,_codeSet());
        vm.expectRevert(EnclaveSecretVaultV2.BadMachine.selector);
        vault.createIndependentCommittee("independent",ms,cs,_codeSet(),sigs,hosts);
        ms[1] = _machineOn(810,_host(810,vm.addr(900)));
        hosts=_hostSigs(ms); sigs=_independentSigs(ms,cs,_codeSet());
        vm.expectRevert(EnclaveSecretVaultV2.BadMachine.selector);
        vault.createIndependentCommittee("independent",ms,cs,_codeSet(),sigs,hosts);
    }
    function test_independentGenesisRejectsEnclaveFounderAndWrongThreshold() public {
        EnclaveSecretVaultV2.Machine[] memory ms = _independentMachines();
        bytes memory cs=bytes.concat(Y,Y);
        bytes[] memory sigs=_independentSigs(ms,cs,_codeSet());
        bytes[] memory hosts=_hostSigs(ms);
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.createIndependentCommittee("independent",ms,Y,_codeSet(),sigs,hosts);
        ms[1]=_machine(820,true);
        hosts=_hostSigs(ms); sigs=_independentSigs(ms,cs,_codeSet());
        vm.expectRevert(EnclaveSecretVaultV2.BadSeats.selector);
        vault.createIndependentCommittee("independent",ms,cs,_codeSet(),sigs,hosts);
    }
    function _genesisDigest(bytes32 cid, EnclaveSecretVaultV2.Machine memory m, bytes32[] memory cs) internal view returns (bytes32) {
        return keccak256(abi.encode("enclave-custody-v2 genesis", block.chainid, address(vault), cid, keccak256(Y), _mh(m), keccak256(abi.encode(cs))));
    }
    function _cid(bytes32 salt) internal view returns (bytes32) { return keccak256(abi.encode(block.chainid, address(vault), salt, keccak256(Y))); }

    function _genesis(EnclaveSecretVaultV2.Machine memory m) internal returns (bytes32 cid) {
        bytes32[] memory cs = _codeSet();
        cid = vault.createCommittee("salt", m, Y, cs, _psign(idKey[m.identity], _genesisDigest(_cid("salt"), m, cs)), _hostSig(m));
    }

    function _hostSigs(EnclaveSecretVaultV2.Machine[] memory next) internal view returns (bytes[] memory s) {
        s = new bytes[](next.length);
        for (uint256 i = 0; i < next.length; i++) s[i] = _hostSig(next[i]);
    }
    function _handoverDigest(bytes32 cid, EnclaveSecretVaultV2.Machine[] memory next, uint32[] memory dealers) internal view returns (bytes32) {
        (, uint32 epoch,,,) = vault.committeeOf(cid);
        bytes32[] memory hs = new bytes32[](next.length);
        for (uint256 i = 0; i < next.length; i++) hs[i] = _mh(next[i]);
        return keccak256(abi.encode("enclave-custody-v2 handover", block.chainid, address(vault), cid, epoch, keccak256(abi.encode(hs)), keccak256(abi.encode(dealers))));
    }
    function _sigs(address[] memory who, bytes32 digest) internal view returns (bytes[] memory s) {
        s = new bytes[](who.length);
        for (uint256 i = 0; i < who.length; i++) s[i] = _psign(idKey[who[i]], digest);
    }
    function _seq(uint256 t) internal pure returns (uint32[] memory d) { d = new uint32[](t); for (uint256 i = 0; i < t; i++) d[i] = uint32(i + 1); }
    function _current(bytes32 cid) internal view returns (address[] memory ids) {
        (, uint32 epoch,,,) = vault.committeeOf(cid);
        (EnclaveSecretVaultV2.Machine[] memory ms,) = vault.machinesOf(cid, epoch);
        ids = new address[](ms.length);
        for (uint256 i = 0; i < ms.length; i++) ids[i] = ms[i].identity;
    }
    function _list(EnclaveSecretVaultV2.Machine memory a) internal pure returns (EnclaveSecretVaultV2.Machine[] memory l) { l = new EnclaveSecretVaultV2.Machine[](1); l[0] = a; }
    function _list(EnclaveSecretVaultV2.Machine memory a, EnclaveSecretVaultV2.Machine memory b) internal pure returns (EnclaveSecretVaultV2.Machine[] memory l) {
        l = new EnclaveSecretVaultV2.Machine[](2); l[0] = a; l[1] = b;
    }
    function _addrs(address a) internal pure returns (address[] memory l) { l = new address[](1); l[0] = a; }

    /// propose with every current machine approving and dealers 1..t_old
    function _propose(bytes32 cid, EnclaveSecretVaultV2.Machine[] memory next) internal returns (uint32 toEpoch) {
        (,, uint8 tOld,,) = vault.committeeOf(cid);
        uint32[] memory dealers = _seq(tOld);
        address[] memory ap = _current(cid);
        vault.proposeHandover(cid, next, _hostSigs(next), dealers, ap, _sigs(ap, _handoverDigest(cid, next, dealers)));
        (toEpoch,,,,,,) = vault.pendingOf(cid);
    }

    /// the test's own copy of protocol.mjs seatLayout: who holds share index k in `epoch`
    function _holder(bytes32 cid, uint32 epoch, uint32 k) internal view returns (address) {
        (EnclaveSecretVaultV2.Machine[] memory ms, bool[] memory enc) = vault.machinesOf(cid, epoch);
        uint256 others; bool hasE;
        for (uint256 i = 0; i < enc.length; i++) { if (enc[i]) hasE = true; else others++; }
        uint256 n = others + (hasE ? 1 : 0);
        uint256 wE = n >= 3 ? (hasE ? 1 : 0) : others + 1;
        if (k <= wE) { for (uint256 i = 0; i < enc.length; i++) if (enc[i]) return ms[i].identity; }
        uint256 next = wE + 1;
        for (uint256 i = 0; i < enc.length; i++) if (!enc[i]) { if (next == k) return ms[i].identity; next++; }
        revert("no holder");
    }
    function _dealDigest(bytes32 cid, uint32 toEpoch, uint32 k, bytes memory com, bytes[] memory sealedTo) internal view returns (bytes32) {
        return keccak256(abi.encode("enclave-custody-v2 deal", block.chainid, address(vault), cid, toEpoch, k, keccak256(com), keccak256(abi.encode(sealedTo))));
    }
    function _dealParts(uint256 tNew, uint256 n) internal pure returns (bytes memory com, bytes[] memory sealedTo) {
        com = new bytes(tNew * 33);
        for (uint256 j = 0; j < tNew; j++) com[j * 33] = 0x02;
        sealedTo = new bytes[](n);
        for (uint256 i = 0; i < n; i++) sealedTo[i] = abi.encodePacked(keccak256(abi.encode(i)), keccak256(abi.encode(i, 1)));
    }
    function _deal(bytes32 cid, uint32 toEpoch, uint32 k, address dealer) internal {
        (,,, uint8 tNew,,,) = vault.pendingOf(cid);
        (, EnclaveSecretVaultV2.Machine[] memory next,,,,,) = vault.pendingOf(cid);
        (bytes memory com, bytes[] memory sealedTo) = _dealParts(tNew, next.length);
        vault.postDeal(cid, toEpoch, k, com, sealedTo, dealer, _psign(idKey[dealer], _dealDigest(cid, toEpoch, k, com, sealedTo)));
    }
    function _newCommitments(uint256 tNew, uint8 tag) internal view returns (bytes memory c) {
        c = bytes.concat(Y, new bytes((tNew - 1) * 33));
        if (tNew > 1) c[33] = bytes1(tag);
    }
    function _ackSig(bytes32 cid, uint32 toEpoch, bytes memory com, address who) internal view returns (bytes memory) {
        return _psign(idKey[who], keccak256(abi.encode("enclave-custody-v2 ack", block.chainid, address(vault), cid, toEpoch, keccak256(com))));
    }
    function _ackAll(bytes32 cid, uint32 toEpoch) internal {
        (, EnclaveSecretVaultV2.Machine[] memory next,, uint8 tNew,,,) = vault.pendingOf(cid);
        bytes memory com = _newCommitments(tNew, 7);
        for (uint256 i = 0; i < next.length; i++) vault.ackHandover(cid, toEpoch, com, next[i].identity, _ackSig(cid, toEpoch, com, next[i].identity));
    }
    /// a whole handover: propose (all current machines approve), every dealer deals, every new machine acks
    function _handover(bytes32 cid, EnclaveSecretVaultV2.Machine[] memory next) internal returns (uint32 toEpoch) {
        (, uint32 epoch,,,) = vault.committeeOf(cid);
        toEpoch = _propose(cid, next);
        (,,,,, uint32[] memory dealers,) = vault.pendingOf(cid);
        for (uint256 i = 0; i < dealers.length; i++) _deal(cid, toEpoch, dealers[i], _holder(cid, epoch, dealers[i]));
        _ackAll(cid, toEpoch);
        (, uint32 now_,,,) = vault.committeeOf(cid);
        assertEq(now_, toEpoch);
    }

    // ================================================================= genesis
    function test_genesisState() public {
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        assertEq(vault.machineHash(e), _mh(e));
        bytes32 cid = _genesis(e);
        assertEq(cid, _cid("salt"));
        (bytes memory y, uint32 epoch, uint8 t, uint8 W, uint64 at) = vault.committeeOf(cid);
        assertEq(y, Y); assertEq(epoch, 1); assertEq(t, 1); assertEq(W, 1); assertEq(at, block.timestamp);
        (EnclaveSecretVaultV2.Machine[] memory ms, bool[] memory enc) = vault.machinesOf(cid, 1);
        assertEq(ms.length, 1); assertEq(ms[0].identity, e.identity); assertTrue(enc[0]);
        assertEq(vault.commitmentsOf(cid, 1), Y);
        assertEq(vault.codeActiveAt(cid, M), block.timestamp);
        // the same committee id twice
        bytes32[] memory cs = _codeSet();
        bytes memory idSig = _psign(idKey[e.identity], _genesisDigest(cid, e, cs));
        bytes memory hSig = _hostSig(e);
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, hSig);
    }

    function test_genesisRequiresAnEnclaveOwnedMachine() public {
        bytes32[] memory cs = _codeSet();
        // payout wallet is someone else's
        EnclaveSecretVaultV2.Machine memory a = _machine(2, false);
        bytes memory idSig = _psign(idKey[a.identity], _genesisDigest(_cid("salt"), a, cs));
        bytes memory hSig = _hostSig(a);
        vm.expectRevert(EnclaveSecretVaultV2.NotEnclave.selector);
        vault.createCommittee("salt", a, Y, cs, idSig, hSig);
        // no accepted ownership at all
        EnclaveSecretVaultV2.Machine memory b = _machineOn(3, _host(3, address(0)));
        idSig = _psign(idKey[b.identity], _genesisDigest(_cid("salt"), b, cs));
        hSig = _hostSig(b);
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.createCommittee("salt", b, Y, cs, idSig, hSig);
        // ownership transfers: the former owner no longer classifies this host
        EnclaveSecretVaultV2.Machine memory e = _machine(4, true);
        vm.prank(enclaveOwner); ownership.proposeOwner(e.registryId,otherWallet);
        vm.prank(otherWallet); ownership.acceptOwner(e.registryId);
        idSig = _psign(idKey[e.identity], _genesisDigest(_cid("salt"), e, cs));
        hSig = _hostSig(e);
        vm.expectRevert(EnclaveSecretVaultV2.NotEnclave.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, hSig);
    }

    function test_genesisRequiresTheHostSignature() public {
        bytes32[] memory cs = _codeSet();
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        bytes memory idSig = _psign(idKey[e.identity], _genesisDigest(_cid("salt"), e, cs));
        // signed by someone other than the registry entry's operator (here: the machine's own identity)
        bytes memory wrong = _psign(idKey[e.identity], _hostDigest(e));
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, wrong);
        // the operator's signature over a different machine (another endpoint)
        EnclaveSecretVaultV2.Machine memory e2 = EnclaveSecretVaultV2.Machine(e.identity, e.encKey, "https://elsewhere.example", e.chipId, e.registryId, e.measurement);
        wrong = _hostSig(e2);
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, wrong);
        // a high-s form of the operator's own valid signature is refused (EIP-2)
        bytes memory good = _hostSig(e);
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, _highS(good));
        // an inactive (deregistered) host
        vm.prank(vm.addr(opKey[e.registryId])); registry.deregister(e.registryId);
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, good);
        // an unregistered host id
        EnclaveSecretVaultV2.Machine memory u = _machineOn(9, keccak256("no-such-host"));
        opKey[u.registryId] = 0x2009;
        idSig = _psign(idKey[u.identity], _genesisDigest(_cid("salt"), u, cs));
        bytes memory hs = _hostSig(u);
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.createCommittee("salt", u, Y, cs, idSig, hs);
        // an address-book edit cannot change the pinned host registry
        book.set("registry", address(0));
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.createCommittee("salt", u, Y, cs, idSig, hs);
    }
    function _highS(bytes memory sig) internal pure returns (bytes memory) {
        bytes32 r; bytes32 s; uint8 v;
        assembly { r := mload(add(sig, 32)) s := mload(add(sig, 64)) v := byte(0, mload(add(sig, 96))) }
        // s' = n - s (n = the secp256k1 group order) with the other parity: the same signature in its high-s form
        return abi.encodePacked(r, bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s)), v == 27 ? uint8(28) : uint8(27));
    }

    function test_genesisRequiresTheIdentitySignatureAndCode() public {
        bytes32[] memory cs = _codeSet();
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        bytes memory hSig = _hostSig(e);
        // signed by the host operator, not the machine identity
        bytes memory idSig = _psign(opKey[e.registryId], _genesisDigest(_cid("salt"), e, cs));
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, hSig);
        // the identity signed a different code set
        bytes32[] memory other = new bytes32[](2); other[0] = M; other[1] = M2;
        idSig = _psign(idKey[e.identity], _genesisDigest(_cid("salt"), e, other));
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.createCommittee("salt", e, Y, cs, idSig, hSig);
        // v outside {27, 28}
        idSig = _psign(idKey[e.identity], _genesisDigest(_cid("salt"), e, cs));
        bytes memory v0 = bytes.concat(idSig); v0[64] = bytes1(uint8(v0[64]) - 27);
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.createCommittee("salt", e, Y, cs, v0, hSig);
        // the machine's measurement is not in the code set
        bytes32[] memory notM = new bytes32[](1); notM[0] = M2;
        vm.expectRevert(EnclaveSecretVaultV2.BadCode.selector);
        vault.createCommittee("salt", e, Y, notM, _psign(idKey[e.identity], _genesisDigest(_cid("salt"), e, notM)), hSig);
        // Y is not a compressed point
        bytes memory badY = bytes.concat(Y); badY[0] = 0x04;
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.createCommittee("salt", e, badY, cs, idSig, hSig);
        // all good
        vault.createCommittee("salt", e, Y, cs, idSig, hSig);
    }

    // ================================================================= seats
    function _pendingTW(bytes32 cid) internal view returns (uint8 t, uint8 W) { (,,, t, W,,) = vault.pendingOf(cid); }

    function test_seatLayouts() public {
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        EnclaveSecretVaultV2.Machine memory e2 = _machine(2, true);
        EnclaveSecretVaultV2.Machine memory e3 = _machine(3, true);
        EnclaveSecretVaultV2.Machine memory a = _machine(11, false);
        EnclaveSecretVaultV2.Machine memory b = _machine(12, false);
        EnclaveSecretVaultV2.Machine memory c = _machine(13, false);
        EnclaveSecretVaultV2.Machine memory d = _machine(14, false);
        bytes32 cid = _genesis(e);

        // 1 seat (Enclave): t 1, W 1
        _propose(cid, _list(e));
        (uint8 t, uint8 W) = _pendingTW(cid); assertEq(t, 1); assertEq(W, 1);
        // fewer than 3 seats without the Enclave seat: refused
        EnclaveSecretVaultV2.Machine[] memory ab = _list(a, b);
        bytes[] memory hs = _hostSigs(ab);
        uint32[] memory dl = _seq(1);
        address[] memory ap = _addrs(e.identity);
        bytes[] memory sg = _sigs(ap, _handoverDigest(cid, ab, dl));
        vm.warp(block.timestamp + 1 days);                         // the pending one expired: replaceable
        vm.expectRevert(EnclaveSecretVaultV2.BadSeats.selector);
        vault.proposeHandover(cid, ab, hs, dl, ap, sg);
        EnclaveSecretVaultV2.Machine[] memory only = _list(a);
        hs = _hostSigs(only);
        sg = _sigs(ap, _handoverDigest(cid, only, dl));
        vm.expectRevert(EnclaveSecretVaultV2.BadSeats.selector);
        vault.proposeHandover(cid, only, hs, dl, ap, sg);
        // 2 seats: Enclave + a -> t 2, the Enclave seat holds 2 shares (W 3)
        _propose(cid, _list(e, a));
        (t, W) = _pendingTW(cid); assertEq(t, 2); assertEq(W, 3);
        // 3 seats: t 2, W 3
        EnclaveSecretVaultV2.Machine[] memory l = new EnclaveSecretVaultV2.Machine[](3);
        l[0] = e; l[1] = a; l[2] = b;
        vm.warp(block.timestamp + 1 days);
        _propose(cid, l);
        (t, W) = _pendingTW(cid); assertEq(t, 2); assertEq(W, 3);
        // 4 seats: t 3
        l = new EnclaveSecretVaultV2.Machine[](4); l[0] = a; l[1] = e; l[2] = b; l[3] = c;
        vm.warp(block.timestamp + 1 days);
        _propose(cid, l);
        (t, W) = _pendingTW(cid); assertEq(t, 3); assertEq(W, 4);
        // 5 seats: t 4
        l = new EnclaveSecretVaultV2.Machine[](5); l[0] = e; l[1] = a; l[2] = b; l[3] = c; l[4] = d;
        vm.warp(block.timestamp + 1 days);
        _propose(cid, l);
        (t, W) = _pendingTW(cid); assertEq(t, 4); assertEq(W, 5);
        // 3 non-Enclave seats and no Enclave seat at all: allowed at n >= 3
        l = new EnclaveSecretVaultV2.Machine[](3); l[0] = a; l[1] = b; l[2] = c;
        vm.warp(block.timestamp + 1 days);
        _propose(cid, l);
        (t, W) = _pendingTW(cid); assertEq(t, 2); assertEq(W, 3);
        // three Enclave machines + one other host: still 2 seats (t 2, W 3), not 4
        l = new EnclaveSecretVaultV2.Machine[](4); l[0] = e; l[1] = a; l[2] = e2; l[3] = e3;
        vm.warp(block.timestamp + 1 days);
        _propose(cid, l);
        (t, W) = _pendingTW(cid); assertEq(t, 2); assertEq(W, 3);
        (, , bool[] memory enc,,,,) = vault.pendingOf(cid);
        assertTrue(enc[0]); assertFalse(enc[1]); assertTrue(enc[2]); assertTrue(enc[3]);
        // two Enclave machines + three others: 4 seats, t 3, W 4
        l = new EnclaveSecretVaultV2.Machine[](5); l[0] = e; l[1] = e2; l[2] = a; l[3] = b; l[4] = c;
        vm.warp(block.timestamp + 1 days);
        _propose(cid, l);
        (t, W) = _pendingTW(cid); assertEq(t, 3); assertEq(W, 4);
        // only Enclave machines: one seat
        l = new EnclaveSecretVaultV2.Machine[](3); l[0] = e; l[1] = e2; l[2] = e3;
        vm.warp(block.timestamp + 1 days);
        _propose(cid, l);
        (t, W) = _pendingTW(cid); assertEq(t, 1); assertEq(W, 1);
    }

    function test_seatShareIndicesFollowTheLayout() public {
        // [a, e, b, e2, c]: 4 seats (t 3); the Enclave seat is index 1 (e AND e2), then a 2, b 3, c 4
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        bytes32 cid = _genesis(e);
        EnclaveSecretVaultV2.Machine[] memory l = new EnclaveSecretVaultV2.Machine[](5);
        l[0] = _machine(11, false); l[1] = e; l[2] = _machine(12, false); l[3] = _machine(2, true); l[4] = _machine(13, false);
        _handover(cid, l);
        (, uint32 epoch, uint8 t, uint8 W,) = vault.committeeOf(cid);
        assertEq(epoch, 2); assertEq(t, 3); assertEq(W, 4);
        assertEq(_holder(cid, 2, 1), e.identity);
        assertEq(_holder(cid, 2, 2), l[0].identity);
        assertEq(_holder(cid, 2, 4), l[4].identity);
        // the contract agrees: the next handover's dealer index 1 is dealt by e2 (an Enclave replica), 2 by l[0], 3 by l[2]
        // (postDeal checks the dealer holds the index; see test_postDealOnlyByTheHolderOfThatIndex for the refusals)
        uint32 to = _propose(cid, _list(e, l[0]));
        _deal(cid, to, 1, l[3].identity);
        _deal(cid, to, 2, l[0].identity);
        (,,, uint8 tNew,,,) = vault.pendingOf(cid);
        (bytes memory com, bytes[] memory st) = _dealParts(tNew, 2);
        bytes memory sig = _psign(idKey[l[2].identity], _dealDigest(cid, to, 3, com, st));
        vault.postDeal(cid, to, 3, com, st, l[2].identity, sig);
    }

    // ================================================================= handover approvals
    function _fiveSeatCommittee() internal returns (bytes32 cid, EnclaveSecretVaultV2.Machine[] memory l) {
        // [e, e2, a, b, c] = 4 seats, t 3
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        cid = _genesis(e);
        l = new EnclaveSecretVaultV2.Machine[](5);
        l[0] = e; l[1] = _machine(2, true); l[2] = _machine(11, false); l[3] = _machine(12, false); l[4] = _machine(13, false);
        _handover(cid, l);
    }

    function test_handoverApprovalWeightCountsTheEnclaveSeatOnce() public {
        (bytes32 cid, EnclaveSecretVaultV2.Machine[] memory l) = _fiveSeatCommittee();
        EnclaveSecretVaultV2.Machine[] memory next = l;
        bytes[] memory hs = _hostSigs(next);
        uint32[] memory dl = _seq(3);
        bytes32 dig = _handoverDigest(cid, next, dl);
        // both Enclave machines: one seat, weight 1
        address[] memory ap = new address[](2); ap[0] = l[0].identity; ap[1] = l[1].identity;
        vm.expectRevert(abi.encodeWithSelector(EnclaveSecretVaultV2.Weight.selector, uint256(1), uint256(3)));
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
        // both Enclave machines + a: weight 2
        ap = new address[](3); ap[0] = l[0].identity; ap[1] = l[1].identity; ap[2] = l[2].identity;
        vm.expectRevert(abi.encodeWithSelector(EnclaveSecretVaultV2.Weight.selector, uint256(2), uint256(3)));
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
        // a twice + b: weight 2 (a machine counts once)
        ap = new address[](3); ap[0] = l[2].identity; ap[1] = l[2].identity; ap[2] = l[3].identity;
        vm.expectRevert(abi.encodeWithSelector(EnclaveSecretVaultV2.Weight.selector, uint256(2), uint256(3)));
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
        // a stranger's signature is not a current machine
        address s = vm.addr(0x5555); idKey[s] = 0x5555;
        ap = new address[](3); ap[0] = l[2].identity; ap[1] = l[3].identity; ap[2] = s;
        vm.expectRevert(EnclaveSecretVaultV2.NotMachine.selector);
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
        // a signature by the wrong key for an approver
        ap = new address[](3); ap[0] = l[2].identity; ap[1] = l[3].identity; ap[2] = l[4].identity;
        bytes[] memory sg = _sigs(ap, dig); sg[2] = _psign(0x5555, dig);
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.proposeHandover(cid, next, hs, dl, ap, sg);
        // a signature over another proposal (other dealers)
        sg = _sigs(ap, _handoverDigest(cid, next, _seq(2)));
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.proposeHandover(cid, next, hs, dl, ap, sg);
        // three non-Enclave seats: weight 3
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
        vm.warp(block.timestamp + 1 days);
        // one Enclave machine + two others: weight 3
        ap = new address[](3); ap[0] = l[1].identity; ap[1] = l[2].identity; ap[2] = l[4].identity;
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
    }

    function test_twoSeatCommitteeEnclaveAloneApproves() public {
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        EnclaveSecretVaultV2.Machine memory a = _machine(11, false);
        bytes32 cid = _genesis(e);
        _handover(cid, _list(e, a));                       // t 2, Enclave holds 1,2; a holds 3
        EnclaveSecretVaultV2.Machine[] memory next = _list(e, a);
        bytes[] memory hs = _hostSigs(next);
        uint32[] memory dl = _seq(2);
        bytes32 dig = _handoverDigest(cid, next, dl);
        address[] memory ap = _addrs(a.identity);
        vm.expectRevert(abi.encodeWithSelector(EnclaveSecretVaultV2.Weight.selector, uint256(1), uint256(2)));
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
        ap = _addrs(e.identity);
        vault.proposeHandover(cid, next, hs, dl, ap, _sigs(ap, dig));
        // the Enclave machine deals both of its indices; a cannot deal index 1
        (, uint32 epoch,,,) = vault.committeeOf(cid);
        (uint32 to,,,,,,) = vault.pendingOf(cid);
        (bytes memory com, bytes[] memory st) = _dealParts(2, 2);
        bytes memory sig = _psign(idKey[a.identity], _dealDigest(cid, to, 1, com, st));
        vm.expectRevert(EnclaveSecretVaultV2.BadDealers.selector);
        vault.postDeal(cid, to, 1, com, st, a.identity, sig);
        _deal(cid, to, 1, e.identity);
        _deal(cid, to, 2, e.identity);
        _ackAll(cid, to);
        (, uint32 e2,,,) = vault.committeeOf(cid);
        assertEq(e2, epoch + 1);
    }

    function test_dealerIndicesAreValidated() public {
        (bytes32 cid, EnclaveSecretVaultV2.Machine[] memory l) = _fiveSeatCommittee();   // t 3, W 4
        bytes[] memory hs = _hostSigs(l);
        address[] memory ap = _current(cid);
        uint32[][] memory bad = new uint32[][](5);
        bad[0] = _seq(2);                                               // too few
        bad[1] = _seq(4);                                               // too many
        bad[2] = new uint32[](3); bad[2][0] = 0; bad[2][1] = 1; bad[2][2] = 2;     // index 0
        bad[3] = new uint32[](3); bad[3][0] = 1; bad[3][1] = 2; bad[3][2] = 5;     // above W
        bad[4] = new uint32[](3); bad[4][0] = 2; bad[4][1] = 3; bad[4][2] = 2;     // duplicate
        for (uint256 i = 0; i < bad.length; i++) {
            bytes[] memory sg = _sigs(ap, _handoverDigest(cid, l, bad[i]));
            vm.expectRevert(EnclaveSecretVaultV2.BadDealers.selector);
            vault.proposeHandover(cid, l, hs, bad[i], ap, sg);
        }
        uint32[] memory ok = new uint32[](3); ok[0] = 4; ok[1] = 1; ok[2] = 3;
        vault.proposeHandover(cid, l, hs, ok, ap, _sigs(ap, _handoverDigest(cid, l, ok)));
        (,,,,, uint32[] memory dealers,) = vault.pendingOf(cid);
        assertEq(dealers.length, 3); assertEq(dealers[0], 4);
    }

    function test_postDealOnlyByTheHolderOfThatIndex() public {
        (bytes32 cid, EnclaveSecretVaultV2.Machine[] memory l) = _fiveSeatCommittee();   // e,e2 -> 1; a 2; b 3; c 4
        uint32[] memory dl = new uint32[](3); dl[0] = 1; dl[1] = 2; dl[2] = 3;
        address[] memory ap = _current(cid);
        vault.proposeHandover(cid, l, _hostSigs(l), dl, ap, _sigs(ap, _handoverDigest(cid, l, dl)));
        (uint32 to,,, uint8 tNew,,,) = vault.pendingOf(cid);
        (bytes memory com, bytes[] memory st) = _dealParts(tNew, l.length);
        // b (index 3) posting index 2
        bytes memory sig = _psign(idKey[l[3].identity], _dealDigest(cid, to, 2, com, st));
        vm.expectRevert(EnclaveSecretVaultV2.BadDealers.selector);
        vault.postDeal(cid, to, 2, com, st, l[3].identity, sig);
        // index 4 is c's, but not one of the proposal's dealers
        sig = _psign(idKey[l[4].identity], _dealDigest(cid, to, 4, com, st));
        vm.expectRevert(EnclaveSecretVaultV2.BadDealers.selector);
        vault.postDeal(cid, to, 4, com, st, l[4].identity, sig);
        // a non-machine
        address s = vm.addr(0x5555);
        sig = _psign(0x5555, _dealDigest(cid, to, 2, com, st));
        vm.expectRevert(EnclaveSecretVaultV2.NotMachine.selector);
        vault.postDeal(cid, to, 2, com, st, s, sig);
        // a's index, signed by someone else
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.postDeal(cid, to, 2, com, st, l[2].identity, sig);
        // shape: wrong commitment count, wrong envelope count, empty envelope
        bytes memory shortCom = new bytes((tNew - 1) * 33);
        vm.expectRevert(EnclaveSecretVaultV2.BadDeal.selector);
        vault.postDeal(cid, to, 2, shortCom, st, l[2].identity, _psign(idKey[l[2].identity], _dealDigest(cid, to, 2, shortCom, st)));
        bytes[] memory fewer = new bytes[](4);
        for (uint256 i = 0; i < 4; i++) fewer[i] = st[i];
        vm.expectRevert(EnclaveSecretVaultV2.BadDeal.selector);
        vault.postDeal(cid, to, 2, com, fewer, l[2].identity, _psign(idKey[l[2].identity], _dealDigest(cid, to, 2, com, fewer)));
        // the wrong toEpoch
        vm.expectRevert(EnclaveSecretVaultV2.NoPending.selector);
        vault.postDeal(cid, to + 1, 2, com, st, l[2].identity, sig);
        // the Enclave replica e2 deals the Enclave seat's index; a deals its own; once per index
        _deal(cid, to, 1, l[1].identity);
        vm.expectRevert(EnclaveSecretVaultV2.BadDealers.selector);
        this.dealExt(cid, to, 1, l[0].identity);
        _deal(cid, to, 2, l[2].identity);
        (bytes memory gotCom, bytes[] memory gotSt) = vault.dealOf(cid, to, 2);
        assertEq(keccak256(gotCom), keccak256(com)); assertEq(gotSt.length, 5); assertEq(keccak256(gotSt[4]), keccak256(st[4]));
    }
    function dealExt(bytes32 cid, uint32 to, uint32 k, address dealer) external { _deal(cid, to, k, dealer); }

    function test_ackRulesAndActivation() public {
        (bytes32 cid, EnclaveSecretVaultV2.Machine[] memory l) = _fiveSeatCommittee();
        // next: drop c -> [e, e2, a, b] = 3 seats, t 2
        EnclaveSecretVaultV2.Machine[] memory next = new EnclaveSecretVaultV2.Machine[](4);
        for (uint256 i = 0; i < 4; i++) next[i] = l[i];
        uint32 to = _propose(cid, next);
        (,,, uint8 tNew,,,) = vault.pendingOf(cid);
        assertEq(tNew, 2);
        bytes memory com = _newCommitments(tNew, 7);
        // acks wait for every dealer's deal
        bytes memory sig = _ackSig(cid, to, com, next[0].identity);
        vm.expectRevert(EnclaveSecretVaultV2.BadAck.selector);
        vault.ackHandover(cid, to, com, next[0].identity, sig);
        _deal(cid, to, 1, l[0].identity);
        _deal(cid, to, 2, l[2].identity);
        _deal(cid, to, 3, l[3].identity);
        // C0 != Y
        bytes memory badC0 = bytes.concat(com); badC0[1] = bytes1(uint8(badC0[1]) ^ 1);
        vm.expectRevert(EnclaveSecretVaultV2.BadAck.selector);
        vault.ackHandover(cid, to, badC0, next[0].identity, _ackSig(cid, to, badC0, next[0].identity));
        // the wrong length (t_new - 1 points)
        bytes memory shortCom = Y;
        vm.expectRevert(EnclaveSecretVaultV2.BadAck.selector);
        vault.ackHandover(cid, to, shortCom, next[0].identity, _ackSig(cid, to, shortCom, next[0].identity));
        // c is not in next
        vm.expectRevert(EnclaveSecretVaultV2.NotMachine.selector);
        vault.ackHandover(cid, to, com, l[4].identity, _ackSig(cid, to, com, l[4].identity));
        // a signature by another machine
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.ackHandover(cid, to, com, next[1].identity, sig);
        vault.ackHandover(cid, to, com, next[0].identity, sig);
        assertEq(vault.ackCount(cid, to), 1);
        // twice
        vm.expectRevert(EnclaveSecretVaultV2.BadAck.selector);
        vault.ackHandover(cid, to, com, next[0].identity, sig);
        // different commitments from the first ack
        bytes memory other = _newCommitments(tNew, 9);
        vm.expectRevert(EnclaveSecretVaultV2.BadAck.selector);
        vault.ackHandover(cid, to, other, next[1].identity, _ackSig(cid, to, other, next[1].identity));
        vault.ackHandover(cid, to, com, next[1].identity, _ackSig(cid, to, com, next[1].identity));
        vault.ackHandover(cid, to, com, next[2].identity, _ackSig(cid, to, com, next[2].identity));
        (, uint32 epoch,,,) = vault.committeeOf(cid);
        assertEq(epoch, to - 1);                           // 3 of 4: not yet
        vm.expectEmit(true, false, false, true);
        emit EnclaveSecretVaultV2.EpochActivated(cid, to);
        vault.ackHandover(cid, to, com, next[3].identity, _ackSig(cid, to, com, next[3].identity));
        (bytes memory y, uint32 e2, uint8 t, uint8 W, uint64 at) = vault.committeeOf(cid);
        assertEq(y, Y); assertEq(e2, to); assertEq(t, 2); assertEq(W, 3); assertEq(at, block.timestamp);
        assertEq(vault.commitmentsOf(cid, to), com);
        (EnclaveSecretVaultV2.Machine[] memory ms,) = vault.machinesOf(cid, to);
        assertEq(ms.length, 4);
        (uint32 pend,,,,,,) = vault.pendingOf(cid);
        assertEq(pend, 0);
        // the old machine c is no longer an approver
        address[] memory ap = _addrs(l[4].identity);
        uint32[] memory dl = _seq(2);
        bytes[] memory sg = _sigs(ap, _handoverDigest(cid, next, dl));
        bytes[] memory hs = _hostSigs(next);
        vm.expectRevert(EnclaveSecretVaultV2.NotMachine.selector);
        vault.proposeHandover(cid, next, hs, dl, ap, sg);
    }

    function test_expiredPendingProposalIsReplaceable() public {
        (bytes32 cid, EnclaveSecretVaultV2.Machine[] memory l) = _fiveSeatCommittee();
        (, uint32 epoch,,,) = vault.committeeOf(cid);
        uint32 to = _propose(cid, l);
        assertEq(to, epoch + 1);
        (,,,,,, uint64 expires) = vault.pendingOf(cid);
        assertEq(expires, block.timestamp + 1 days);
        _deal(cid, to, 1, l[0].identity);
        // a second proposal before expiry
        EnclaveSecretVaultV2.Machine[] memory next = new EnclaveSecretVaultV2.Machine[](4);
        for (uint256 i = 0; i < 4; i++) next[i] = l[i];
        uint32[] memory dl = _seq(3);
        address[] memory ap = _current(cid);
        bytes[] memory hs = _hostSigs(next);
        bytes[] memory sg = _sigs(ap, _handoverDigest(cid, next, dl));
        vm.warp(expires - 1);
        vm.expectRevert(EnclaveSecretVaultV2.Pending.selector);
        vault.proposeHandover(cid, next, hs, dl, ap, sg);
        vm.warp(expires);
        vault.proposeHandover(cid, next, hs, dl, ap, sg);
        // the replacement takes a FRESH epoch number, so the replaced round's deals and acks cannot be replayed into it
        (uint32 to2, EnclaveSecretVaultV2.Machine[] memory pn,,,,,) = vault.pendingOf(cid);
        assertEq(to2, to + 1); assertEq(pn.length, 4);
        vm.expectRevert(EnclaveSecretVaultV2.NoPending.selector);
        this.dealExt(cid, to, 2, l[2].identity);
        (bytes memory oldCom,) = vault.dealOf(cid, to2, 1);
        assertEq(oldCom.length, 0);
        _deal(cid, to2, 1, l[0].identity);
        _deal(cid, to2, 2, l[2].identity);
        _deal(cid, to2, 3, l[3].identity);
        _ackAll(cid, to2);
        (, uint32 now_,,,) = vault.committeeOf(cid);
        assertEq(now_, to2);
    }

    // ================================================================= code set
    function _codeSigs(bytes32 cid, bytes32 m, bool add, address[] memory ap) internal view returns (bytes[] memory) {
        (, uint32 epoch,,,) = vault.committeeOf(cid);
        return _sigs(ap, keccak256(abi.encode("enclave-custody-v2 code", block.chainid, address(vault), cid, epoch, m, add)));
    }

    function test_proposeCodeIsTimelockedAndRemoveIsImmediate() public {
        (bytes32 cid, EnclaveSecretVaultV2.Machine[] memory l) = _fiveSeatCommittee();
        // weight: two Enclave machines + a = 2 < 3
        address[] memory weak = new address[](3); weak[0] = l[0].identity; weak[1] = l[1].identity; weak[2] = l[2].identity;
        bytes[] memory weakSigs = _codeSigs(cid, M2, true, weak);
        vm.expectRevert(abi.encodeWithSelector(EnclaveSecretVaultV2.Weight.selector, uint256(2), uint256(3)));
        vault.proposeCode(cid, M2, weak, weakSigs);
        address[] memory ap = new address[](3); ap[0] = l[0].identity; ap[1] = l[2].identity; ap[2] = l[3].identity;
        // an approval for removal does not add
        bytes[] memory rm = _codeSigs(cid, M2, false, ap);
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.proposeCode(cid, M2, ap, rm);
        bytes[] memory add = _codeSigs(cid, M2, true, ap);
        vault.proposeCode(cid, M2, ap, add);
        uint64 activeAt = uint64(block.timestamp) + 7 days;
        assertEq(vault.codeActiveAt(cid, M2), activeAt);
        // the same approvals again: consumed
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.proposeCode(cid, M2, ap, add);

        // a machine running M2 cannot join before the delay has passed
        EnclaveSecretVaultV2.Machine[] memory next = new EnclaveSecretVaultV2.Machine[](5);
        for (uint256 i = 0; i < 5; i++) next[i] = l[i];
        EnclaveSecretVaultV2.Machine memory up = _machine(21, false); up.measurement = M2;
        next[4] = up;
        uint32[] memory dl = _seq(3);
        bytes[] memory hs = _hostSigs(next);
        address[] memory all = _current(cid);
        bytes[] memory sg = _sigs(all, _handoverDigest(cid, next, dl));
        vm.warp(activeAt - 1);
        vm.expectRevert(EnclaveSecretVaultV2.BadCode.selector);
        vault.proposeHandover(cid, next, hs, dl, all, sg);
        vm.warp(activeAt);
        vault.proposeHandover(cid, next, hs, dl, all, sg);
        (uint32 to,,,,,,) = vault.pendingOf(cid);

        // removing M2 is immediate, and a pending handover onto it can no longer activate
        rm = _codeSigs(cid, M2, false, ap);
        vault.removeCode(cid, M2, ap, rm);
        assertEq(vault.codeActiveAt(cid, M2), 0);
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.removeCode(cid, M2, ap, rm);                 // consumed
        _deal(cid, to, 1, l[0].identity);
        _deal(cid, to, 2, l[2].identity);
        _deal(cid, to, 3, l[3].identity);
        (,,, uint8 tNew,,,) = vault.pendingOf(cid);
        bytes memory com = _newCommitments(tNew, 7);
        for (uint256 i = 0; i < 4; i++) vault.ackHandover(cid, to, com, next[i].identity, _ackSig(cid, to, com, next[i].identity));
        bytes memory last = _ackSig(cid, to, com, next[4].identity);
        vm.expectRevert(EnclaveSecretVaultV2.BadCode.selector);
        vault.ackHandover(cid, to, com, next[4].identity, last);
        // removing something not in the set; proposing the zero measurement
        bytes[] memory rm3 = _codeSigs(cid, keccak256("never"), false, ap);
        vm.expectRevert(EnclaveSecretVaultV2.BadCode.selector);
        vault.removeCode(cid, keccak256("never"), ap, rm3);
        bytes[] memory z = _codeSigs(cid, bytes32(0), true, ap);
        vm.expectRevert(EnclaveSecretVaultV2.BadCode.selector);
        vault.proposeCode(cid, bytes32(0), ap, z);
        // the genesis code can be removed at once too
        bytes[] memory rmM = _codeSigs(cid, M, false, ap);
        vault.removeCode(cid, M, ap, rmM);
        assertEq(vault.codeActiveAt(cid, M), 0);
    }

    // ================================================================= Enclave flag and uniqueness
    function test_aHostNamingAnotherWalletIsNotEnclave() public {
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        bytes32 cid = _genesis(e);
        // a host whose payout wallet is NOT the Enclave wallet: listed as a regular seat, whatever it calls itself
        EnclaveSecretVaultV2.Machine memory fake = _machine(30, false);
        fake.endpoint = "https://enclave-official.example";
        _propose(cid, _list(e, fake));
        (,, bool[] memory enc, uint8 t, uint8 W,,) = vault.pendingOf(cid);
        assertTrue(enc[0]); assertFalse(enc[1]); assertEq(t, 2); assertEq(W, 3);
        // nor can it borrow an Enclave host's registry entry: its own operator key does not sign for that entry
        EnclaveSecretVaultV2.Machine memory borrow = _machineOn(31, e.registryId);
        EnclaveSecretVaultV2.Machine[] memory next = _list(e, borrow);
        bytes[] memory hs = new bytes[](2);
        hs[0] = _hostSig(e);
        hs[1] = _psign(0x2000 + 30, _hostDigest(borrow));     // signed by the fake host's operator
        uint32[] memory dl = _seq(1);
        address[] memory ap = _addrs(e.identity);
        bytes[] memory sg = _sigs(ap, _handoverDigest(cid, next, dl));
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(EnclaveSecretVaultV2.BadHost.selector);
        vault.proposeHandover(cid, next, hs, dl, ap, sg);
        // and it cannot open a committee
        bytes32[] memory cs = _codeSet();
        bytes memory idSig = _psign(idKey[fake.identity], _genesisDigest(_cid("x"), fake, cs));
        bytes memory fh = _hostSig(fake);
        vm.expectRevert(EnclaveSecretVaultV2.NotEnclave.selector);
        vault.createCommittee("x", fake, Y, cs, idSig, fh);
    }

    function test_chipIdUniqueAmongNonEnclaveMachines() public {
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        bytes32 cid = _genesis(e);
        EnclaveSecretVaultV2.Machine memory a = _machine(11, false);
        EnclaveSecretVaultV2.Machine memory b = _machine(12, false);
        EnclaveSecretVaultV2.Machine memory e2 = _machine(2, true);
        // two non-Enclave machines on one chip
        b.chipId = a.chipId;
        EnclaveSecretVaultV2.Machine[] memory l = new EnclaveSecretVaultV2.Machine[](3);
        l[0] = e; l[1] = a; l[2] = b;
        bytes[] memory hs = _hostSigs(l);
        uint32[] memory dl = _seq(1);
        address[] memory ap = _addrs(e.identity);
        bytes[] memory sg = _sigs(ap, _handoverDigest(cid, l, dl));
        vm.expectRevert(EnclaveSecretVaultV2.BadMachine.selector);
        vault.proposeHandover(cid, l, hs, dl, ap, sg);
        // the same identity twice
        b = _machine(12, false); b.identity = a.identity;
        l[2] = b; hs = _hostSigs(l); sg = _sigs(ap, _handoverDigest(cid, l, dl));
        vm.expectRevert(EnclaveSecretVaultV2.BadMachine.selector);
        vault.proposeHandover(cid, l, hs, dl, ap, sg);
        // Enclave replicas on one chip (an upgrade in place), and an Enclave machine sharing a chip with another host: fine
        e2.chipId = e.chipId;
        b = _machine(12, false); b.chipId = e.chipId;
        l = new EnclaveSecretVaultV2.Machine[](4); l[0] = e; l[1] = e2; l[2] = a; l[3] = b;
        _propose(cid, l);
        (,, bool[] memory enc, uint8 t,,,) = vault.pendingOf(cid);
        assertTrue(enc[1]); assertEq(t, 2);
        // shape: an empty endpoint, an over-long one
        vm.warp(block.timestamp + 1 days);
        a.endpoint = "";
        l = _list(e, a); hs = _hostSigs(l); sg = _sigs(ap, _handoverDigest(cid, l, dl));
        vm.expectRevert(EnclaveSecretVaultV2.BadMachine.selector);
        vault.proposeHandover(cid, l, hs, dl, ap, sg);
        a.endpoint = string(new bytes(191));
        l = _list(e, a); hs = _hostSigs(l); sg = _sigs(ap, _handoverDigest(cid, l, dl));
        vm.expectRevert(EnclaveSecretVaultV2.BadMachine.selector);
        vault.proposeHandover(cid, l, hs, dl, ap, sg);
    }

    function test_unknownCommitteeAndLimits() public {
        EnclaveSecretVaultV2.Machine[] memory none = new EnclaveSecretVaultV2.Machine[](0);
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.proposeHandover(keccak256("nope"), none, new bytes[](0), new uint32[](0), new address[](0), new bytes[](0));
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.proposeCode(keccak256("nope"), M2, new address[](0), new bytes[](0));
        bytes32 cid = _genesis(_machine(1, true));
        vm.expectRevert(EnclaveSecretVaultV2.BadSeats.selector);
        vault.proposeHandover(cid, none, new bytes[](0), _seq(1), new address[](0), new bytes[](0));
        EnclaveSecretVaultV2.Machine[] memory many = new EnclaveSecretVaultV2.Machine[](97);
        vm.expectRevert(EnclaveSecretVaultV2.BadSeats.selector);
        vault.proposeHandover(cid, many, new bytes[](97), _seq(1), new address[](0), new bytes[](0));
    }

    function test_sixtyFiveSeatsRefusedSixtyFourAccepted() public {
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        bytes32 cid = _genesis(e);
        EnclaveSecretVaultV2.Machine[] memory l = new EnclaveSecretVaultV2.Machine[](65);
        for (uint256 i = 0; i < 65; i++) l[i] = _machine(100 + i, false);
        bytes[] memory hs = _hostSigs(l);
        uint32[] memory dl = _seq(1);
        address[] memory ap = _addrs(e.identity);
        bytes[] memory sg = _sigs(ap, _handoverDigest(cid, l, dl));
        vm.expectRevert(EnclaveSecretVaultV2.BadSeats.selector);
        vault.proposeHandover(cid, l, hs, dl, ap, sg);
        // 64 seats (63 others + the Enclave seat, which has two machines): t = ceil(128/3) = 43
        EnclaveSecretVaultV2.Machine[] memory m = new EnclaveSecretVaultV2.Machine[](65);
        m[0] = e;
        for (uint256 i = 1; i < 64; i++) m[i] = l[i];
        m[64] = _machine(2, true);
        _propose(cid, m);
        (uint8 t, uint8 W) = _pendingTW(cid);
        assertEq(t, 43); assertEq(W, 64);
    }

    /// the spec's maximum: 96 machines (33 Enclave replicas + 63 other hosts = 64 seats), 40-byte endpoints. Reports the gas
    /// of each step (forge test -vv) so the per-transaction gas cap can be judged.
    function test_gasAtTheMaximumCommittee() public {
        EnclaveSecretVaultV2.Machine memory e = _machine(1, true);
        bytes32 cid = _genesis(e);
        EnclaveSecretVaultV2.Machine[] memory l = new EnclaveSecretVaultV2.Machine[](96);
        l[0] = e;
        for (uint256 i = 1; i < 96; i++) {
            l[i] = _machine(200 + i, i < 33);
            l[i].endpoint = string.concat("https://custodian-", vm.toString(200 + i), ".hosts.example.org");
        }
        bytes[] memory hs = _hostSigs(l);
        uint32[] memory dl = _seq(1);
        address[] memory ap = _addrs(e.identity);
        bytes[] memory sg = _sigs(ap, _handoverDigest(cid, l, dl));
        uint256 g = gasleft();
        vault.proposeHandover(cid, l, hs, dl, ap, sg);
        emit log_named_uint("proposeHandover, 96 machines", g - gasleft());
        (uint32 to,,, uint8 tNew,,,) = vault.pendingOf(cid);
        assertEq(tNew, 43);
        (bytes memory com, bytes[] memory st) = _dealParts(tNew, 96);
        for (uint256 i = 0; i < 96; i++) st[i] = new bytes(i < 33 ? 32 + 36 + 16 : 32 + 36 + 16);
        bytes memory sig = _psign(idKey[e.identity], _dealDigest(cid, to, 1, com, st));
        g = gasleft();
        vault.postDeal(cid, to, 1, com, st, e.identity, sig);
        emit log_named_uint("postDeal, 43 commitments, 96 envelopes", g - gasleft());
        bytes memory nc = _newCommitments(tNew, 7);
        uint256 last;
        for (uint256 i = 0; i < 96; i++) {
            bytes memory a = _ackSig(cid, to, nc, l[i].identity);
            g = gasleft();
            vault.ackHandover(cid, to, nc, l[i].identity, a);
            last = g - gasleft();
        }
        emit log_named_uint("ackHandover, the activating 96th", last);
        // a 64-seat committee approves with t = 43 seats
        address[] memory ap2 = new address[](43);
        for (uint256 i = 0; i < 43; i++) ap2[i] = l[53 + i].identity;
        EnclaveSecretVaultV2.Machine[] memory small = _list(e, l[60]);
        uint32[] memory dl2 = _seq(43);
        bytes[] memory hs2 = _hostSigs(small);
        bytes[] memory sg2 = _sigs(ap2, _handoverDigest(cid, small, dl2));
        g = gasleft();
        vault.proposeHandover(cid, small, hs2, dl2, ap2, sg2);
        emit log_named_uint("proposeHandover, 43 approvals over 96 machines", g - gasleft());
    }

    // ================================================================= policies and bundles
    function _committee() internal returns (bytes32) { return _genesis(_machine(1, true)); }
    function _policyOnly(bytes32 cid, uint64 rev) internal pure returns (EnclaveSecretVaultV2.Update memory u) {
        u.expectPolicyRev = rev;
        u.setPolicy = true;
        u.committeeId = cid;
        u.rules = bytes('{"v":1}');
    }
    function _withBundle(bytes32 cid, uint64 rev) internal pure returns (EnclaveSecretVaultV2.Update memory u) {
        u = _policyOnly(cid, rev);
        u.setBundle = true;
        u.bundle = new bytes(200);
        u.bundle[0] = 0x02;
    }
    function _sign712(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_policyAndBundleWithExpectedRevision() public {
        bytes32 cid = _committee();
        vm.prank(stranger);
        vm.expectRevert(EnclaveSecretVaultV2.NotOwner.selector);
        vault.update(D, _policyOnly(cid, 0));
        EnclaveSecretVaultV2.Update memory bare;
        vm.startPrank(owner);
        vm.expectRevert(EnclaveSecretVaultV2.BadRules.selector);
        vault.update(D, bare);
        vault.update(D, _withBundle(cid, 0));
        (address o, uint64 pr, uint64 sr, bytes32 c, bool paused, bytes memory rules) = vault.policyOf(D);
        assertEq(o, owner); assertEq(pr, 1); assertEq(sr, 1); assertEq(c, cid); assertFalse(paused); assertEq(rules, bytes('{"v":1}'));
        (bytes32 bc, uint64 bsr, bytes memory b) = vault.bundleOf(D);
        assertEq(bc, cid); assertEq(bsr, 1); assertEq(b.length, 200);
        vm.expectRevert(abi.encodeWithSelector(EnclaveSecretVaultV2.StaleRevision.selector, uint64(1), uint64(0)));
        vault.update(D, _withBundle(cid, 0));
        vault.update(D, _withBundle(cid, 1));
        (, pr, sr,,,) = vault.policyOf(D);
        assertEq(pr, 2); assertEq(sr, 2);
        // clear
        EnclaveSecretVaultV2.Update memory u;
        u.expectPolicyRev = 2; u.clear = true;
        vault.update(D, u);
        (bc, bsr, b) = vault.bundleOf(D);
        assertEq(bc, bytes32(0)); assertEq(bsr, 3); assertEq(b.length, 0);
        vm.stopPrank();
    }

    function test_bundleNeedsAnExistingCommitteeAndShape() public {
        bytes32 cid = _committee();
        vm.startPrank(owner);
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.update(D, _withBundle(keccak256("no-committee"), 0));
        EnclaveSecretVaultV2.Update memory u = _withBundle(cid, 0); u.bundle = new bytes(124);
        vm.expectRevert(EnclaveSecretVaultV2.BadBundle.selector);
        vault.update(D, u);
        u.bundle = new bytes(24577);
        vm.expectRevert(EnclaveSecretVaultV2.BadBundle.selector);
        vault.update(D, u);
        u = _withBundle(cid, 0); u.clear = true;
        vm.expectRevert(EnclaveSecretVaultV2.BadBundle.selector);
        vault.update(D, u);
        u = _withBundle(cid, 0); u.bundle = new bytes(24576);
        vault.update(D, u);
        vm.stopPrank();
        // moving to another committee with the bundle in place needs a fresh bundle or a clear
        EnclaveSecretVaultV2.Machine memory e2 = _machine(2, true);
        bytes32[] memory cs = _codeSet();
        bytes32 cid2 = vault.createCommittee("salt2", e2, Y, cs, _psign(idKey[e2.identity], _genesisDigest(_cid("salt2"), e2, cs)), _hostSig(e2));
        vm.startPrank(owner);
        u = _policyOnly(cid2, 1);
        vm.expectRevert(EnclaveSecretVaultV2.BadCommittee.selector);
        vault.update(D, u);
        u.setBundle = true; u.bundle = new bytes(130);
        vault.update(D, u);
        (bytes32 bc, uint64 sr,) = vault.bundleOf(D);
        assertEq(bc, cid2); assertEq(sr, 2);
        vm.stopPrank();
    }

    function test_updateBySig() public {
        bytes32 cid = _committee();
        EnclaveSecretVaultV2.Update memory u = _withBundle(cid, 0);
        uint64 deadline = uint64(block.timestamp + 600);
        bytes memory sig = _sign712(ownerKey, vault.updateDigest(D, u, deadline));
        vm.prank(stranger);
        vault.updateBySig(D, u, deadline, sig);
        (, uint64 pr,,,,) = vault.policyOf(D);
        assertEq(pr, 1);
        vm.expectRevert(abi.encodeWithSelector(EnclaveSecretVaultV2.StaleRevision.selector, uint64(1), uint64(0)));
        vault.updateBySig(D, u, deadline, sig);
        EnclaveSecretVaultV2.Update memory u2 = _withBundle(cid, 1);
        bytes memory wrong = _sign712(0xBAD, vault.updateDigest(D, u2, deadline));
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.updateBySig(D, u2, deadline, wrong);
        bytes memory good = _sign712(ownerKey, vault.updateDigest(D, u2, deadline));
        u2.bundle[5] = 0xff;
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.updateBySig(D, u2, deadline, good);
        u2.bundle[5] = 0x00;
        vm.warp(deadline + 1);
        vm.expectRevert(EnclaveSecretVaultV2.Expired.selector);
        vault.updateBySig(D, u2, deadline, good);
        // the domain is V2's own: name "EnclaveSecretVaultV2", version "1"
        assertEq(vault.domainSeparator(), keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256("EnclaveSecretVaultV2"), keccak256("1"), block.chainid, address(vault))));
    }

    function test_contractOwnerSignsWithErc1271() public {
        bytes32 cid = _committee();
        uint256 passkey = 0x9A55;
        V21271 cv = new V21271(vm.addr(passkey));
        bytes32 d2 = keccak256("passkey-deployment");
        ledger.setOwner(d2, address(cv));
        EnclaveSecretVaultV2.Update memory u = _withBundle(cid, 0);
        uint64 deadline = uint64(block.timestamp + 600);
        bytes memory notThePasskey = _sign712(ownerKey, vault.updateDigest(d2, u, deadline));
        vm.expectRevert(EnclaveSecretVaultV2.BadSignature.selector);
        vault.updateBySig(d2, u, deadline, notThePasskey);
        vault.updateBySig(d2, u, deadline, _sign712(passkey, vault.updateDigest(d2, u, deadline)));
        (address o,,,,,) = vault.policyOf(d2);
        assertEq(o, address(cv));
    }

    function test_sessionVaultRecordAnswersToTheVaultOwner() public {
        bytes32 cid = _committee();
        V2SessionVault sv = new V2SessionVault(owner);
        factory.add(address(sv));
        bytes32 d3 = keccak256("session-deployment");
        ledger.setOwner(d3, address(sv));
        assertEq(vault.beneficialOwnerOf(d3), owner);
        vm.prank(address(sv));
        vm.expectRevert(EnclaveSecretVaultV2.NotOwner.selector);
        vault.update(d3, _policyOnly(cid, 0));
        vm.prank(owner);
        vault.update(d3, _policyOnly(cid, 0));
    }

    function test_claimPolicyDestroysTheBundle() public {
        bytes32 cid = _committee();
        vm.prank(owner);
        vault.update(D, _withBundle(cid, 0));
        address newOwner = makeAddr("newOwner");
        ledger.setOwner(D, newOwner);
        vm.prank(owner);
        vm.expectRevert(EnclaveSecretVaultV2.NotOwner.selector);
        vault.update(D, _withBundle(cid, 1));
        vm.prank(newOwner);
        vm.expectRevert(EnclaveSecretVaultV2.NotOwner.selector);
        vault.update(D, _withBundle(cid, 1));
        vm.prank(stranger);
        vm.expectRevert(EnclaveSecretVaultV2.NotOwner.selector);
        vault.claimPolicy(D);
        vm.prank(newOwner);
        vault.claimPolicy(D);
        (address o, uint64 pr, uint64 sr,, bool paused,) = vault.policyOf(D);
        assertEq(o, newOwner); assertEq(pr, 2); assertEq(sr, 2); assertTrue(paused);
        (,, bytes memory b) = vault.bundleOf(D);
        assertEq(b.length, 0);
        vm.prank(newOwner);
        vm.expectRevert(EnclaveSecretVaultV2.NothingToClaim.selector);
        vault.claimPolicy(D);
        // the new owner writes its own policy and bundle
        vm.prank(newOwner);
        vault.update(D, _withBundle(cid, 2));
        (, pr, sr,, paused,) = vault.policyOf(D);
        assertEq(pr, 3); assertEq(sr, 3); assertFalse(paused);
    }

    function testPayoutSpoofDoesNotGrantEnclaveSeat() public {
        EnclaveSecretVaultV2.Machine memory m = _machine(51,false);
        vm.prank(enclaveOwner); registry.setPayoutWallet(m.registryId);
        bytes32[] memory cs = _codeSet();
        bytes memory sig = _psign(idKey[m.identity],_genesisDigest(_cid("salt"),m,cs));
        bytes memory hs = _hostSig(m);
        vm.expectRevert(EnclaveSecretVaultV2.NotEnclave.selector);
        vault.createCommittee("salt",m,Y,cs,sig,hs);
    }
    function testPayoutChangeAndBookEditCannotRemoveAcceptedOwnership() public {
        EnclaveSecretVaultV2.Machine memory m = _machine(52,true);
        vm.prank(stranger); registry.setPayoutWallet(m.registryId);
        book.set("registry",address(0));
        bytes32 cid = _genesis(m);
        (,bool[] memory enc) = vault.machinesOf(cid,1);
        assertTrue(enc[0]);
    }
    function test_constructorAndImmutables() public {
        assertEq(address(vault.hostOwnership()), address(ownership));
        assertEq(vault.hostRegistry(), address(registry));
        assertEq(vault.deploymentLedger(), address(ledger));
        assertEq(vault.sessionVaultFactory(), address(factory));
        assertEq(address(vault.book()), address(book));
        assertEq(vault.enclaveOwner(), enclaveOwner);
        vm.expectRevert();
        new EnclaveSecretVaultV2(address(0), enclaveOwner, address(ownership));
        vm.expectRevert();
        new EnclaveSecretVaultV2(address(book), address(0), address(ownership));
    }

    function testBookCannotRedirectDeploymentOwnership() public {
        V2Ledger substitute = new V2Ledger();
        substitute.setOwner(D, stranger);
        book.set("deployments", address(substitute));
        assertEq(vault.beneficialOwnerOf(D), owner);
        ledger.setOwner(D, otherWallet);
        assertEq(vault.beneficialOwnerOf(D), otherWallet);
        book.set("deployments", address(0));
        assertEq(vault.beneficialOwnerOf(D), otherWallet);
    }

    function testBookCannotDisableSessionOwnershipResolution() public {
        V2SessionVault session = new V2SessionVault(owner);
        factory.add(address(session));
        ledger.setOwner(D, address(session));
        book.set("sessionVaultFactory", address(new V2Factory()));
        assertEq(vault.beneficialOwnerOf(D), owner);
        book.set("sessionVaultFactory", address(0));
        assertEq(vault.beneficialOwnerOf(D), owner);
    }

    function testConstructorRequiresARealLedgerAndOptionalRealFactory() public {
        book.set("deployments", address(0));
        vm.expectRevert(EnclaveSecretVaultV2.NoLedger.selector);
        new EnclaveSecretVaultV2(address(book), enclaveOwner, address(ownership));
        book.set("deployments", address(ledger));
        book.set("sessionVaultFactory", stranger);
        vm.expectRevert();
        new EnclaveSecretVaultV2(address(book), enclaveOwner, address(ownership));
        book.set("sessionVaultFactory", address(0));
        EnclaveSecretVaultV2 noSessions = new EnclaveSecretVaultV2(address(book), enclaveOwner, address(ownership));
        assertEq(noSessions.sessionVaultFactory(), address(0));
    }
}
