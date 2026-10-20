// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;
// EnclaveServiceIndex: only an operator changes its own ads; signatures are bound to this chain and this contract; a
// sequence is never reused; ads expire; the deployer (a "former governor") has no power at all; storage and pages are
// bounded. Run: FOUNDRY_TEST=test forge test --match-path test/EnclaveServiceIndex.t.sol
import "forge-std/Test.sol";
import {EnclaveServiceIndex} from "../contracts/EnclaveServiceIndex.sol";

contract EnclaveServiceIndexTest is Test {
    EnclaveServiceIndex idx;
    address governor = address(0xBEEF);
    uint256 aliceKey = 0xA11CE;
    uint256 bobKey = 0xB0B;
    address alice;
    address bob;
    uint16 constant DIRECTORY = 1;
    uint16 constant CHECKER = 2;

    function setUp() public {
        vm.warp(1_800_000_000);
        vm.prank(governor);
        idx = new EnclaveServiceIndex();
        alice = vm.addr(aliceKey);
        bob = vm.addr(bobKey);
    }

    function eps(string memory a) internal pure returns (string[] memory e) { e = new string[](1); e[0] = a; }
    function exp(uint256 d) internal view returns (uint64) { return uint64(block.timestamp + d); }
    function sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_operatorPublishesReplacesAndWithdrawsOnlyItsOwn() public {
        vm.prank(alice);
        idx.publish(0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), eps("https://dir.alice.example"));
        EnclaveServiceIndex.Ad memory a = idx.get(alice, 0);
        assertEq(a.operator, alice); assertEq(a.endpoints[0], "https://dir.alice.example"); assertEq(idx.count(DIRECTORY), 1);
        // a replacement with a higher sequence, now a checker: moved between kinds
        vm.prank(alice);
        idx.publish(0, CHECKER, 1, 2, exp(7 days), keccak256("d"), eps("https://check.alice.example"));
        assertEq(idx.count(DIRECTORY), 0); assertEq(idx.count(CHECKER), 1);
        assertEq(idx.get(alice, 0).sequence, 2);
        // a stale or equal sequence is refused
        vm.prank(alice); vm.expectRevert("stale sequence");
        idx.publish(0, CHECKER, 1, 2, exp(7 days), bytes32(0), eps("https://x.example"));
        // bob cannot touch alice's slot: his calls act on HIS slots only
        vm.prank(bob);
        idx.withdraw(0, 5);
        assertEq(idx.get(alice, 0).operator, alice, "bob's withdraw removed only his own (empty) slot");
        vm.prank(alice);
        idx.withdraw(0, 3);
        assertEq(idx.get(alice, 0).operator, address(0)); assertEq(idx.count(CHECKER), 0);
        assertEq(idx.sequenceOf(alice, 0), 3, "the sequence survives withdrawal");
    }

    function test_formerGovernorHasNoTakedown() public {
        vm.prank(alice);
        idx.publish(1, DIRECTORY, 1, 1, exp(30 days), bytes32(0), eps("https://dir.alice.example"));
        bytes memory forged = sign(0xDEAD, idx.withdrawDigest(alice, 1, 2));
        vm.startPrank(governor);
        vm.expectRevert("ad is live");
        idx.prune(alice, 1);
        vm.expectRevert("not signed by operator");
        idx.withdrawFor(alice, 1, 2, forged);
        vm.expectRevert("not signed by operator");
        idx.publishFor(alice, 1, DIRECTORY, 1, 9, exp(1 days), bytes32(0), eps("https://evil.example"), hex"");
        vm.stopPrank();
        // no owner, pause or upgrade surface exists at all
        (bool ok,) = address(idx).call(abi.encodeWithSignature("owner()"));
        assertFalse(ok);
        (ok,) = address(idx).call(abi.encodeWithSignature("pause()"));
        assertFalse(ok);
        (ok,) = address(idx).call(abi.encodeWithSignature("transferOwnership(address)", governor));
        assertFalse(ok);
        assertEq(idx.get(alice, 1).endpoints[0], "https://dir.alice.example");
    }

    function test_signedPublishAndWithdrawBindSignerChainAndContract() public {
        string[] memory e = eps("https://dir.alice.example");
        bytes32 d = idx.publishDigest(alice, 0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), e);
        // the wrong signer
        vm.expectRevert("not signed by operator");
        idx.publishFor(alice, 0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), e, sign(bobKey, d));
        // a high-s (malleated) signature
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(aliceKey, d);
        bytes32 highS = bytes32(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - uint256(s));
        vm.expectRevert("not signed by operator");
        idx.publishFor(alice, 0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), e, abi.encodePacked(r, highS, v == 27 ? uint8(28) : uint8(27)));
        // the same signature on another deployment of the index is not valid there
        EnclaveServiceIndex other = new EnclaveServiceIndex();
        vm.expectRevert("not signed by operator");
        other.publishFor(alice, 0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), e, sign(aliceKey, d));
        // ... nor on another chain id
        // (constants, not block.chainid: via-IR may re-read it after the cheatcode changes it)
        vm.chainId(31338);
        vm.expectRevert("not signed by operator");
        idx.publishFor(alice, 0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), e, sign(aliceKey, d));
        vm.chainId(31337);
        // a gas payer (bob) submits alice's signed ad
        vm.prank(bob);
        idx.publishFor(alice, 0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), e, sign(aliceKey, d));
        assertEq(idx.get(alice, 0).operator, alice);
        // replaying it after a withdrawal fails: the sequence moved on
        idx.withdrawFor(alice, 0, 2, sign(aliceKey, idx.withdrawDigest(alice, 0, 2)));
        vm.expectRevert("stale sequence");
        idx.publishFor(alice, 0, DIRECTORY, 1, 1, exp(7 days), bytes32(0), e, sign(aliceKey, d));
    }

    function test_withdrawRevokesASignedPublishNeverSubmitted() public {
        string[] memory e = eps("https://dir.alice.example");
        bytes memory sig = sign(aliceKey, idx.publishDigest(alice, 3, DIRECTORY, 1, 5, exp(7 days), bytes32(0), e));
        vm.prank(alice);
        idx.withdraw(3, 5);
        vm.expectRevert("stale sequence");
        idx.publishFor(alice, 3, DIRECTORY, 1, 5, exp(7 days), bytes32(0), e, sig);
    }

    function test_expiryIsBoundedAndOnlyExpiredAdsArePrunable() public {
        vm.startPrank(alice);
        vm.expectRevert("expiry out of range");
        idx.publish(0, DIRECTORY, 1, 1, uint64(block.timestamp), bytes32(0), eps("https://a.example"));
        vm.expectRevert("expiry out of range");
        idx.publish(0, DIRECTORY, 1, 1, exp(90 days + 1), bytes32(0), eps("https://a.example"));
        idx.publish(0, DIRECTORY, 1, 1, exp(1 days), bytes32(0), eps("https://a.example"));
        vm.stopPrank();
        vm.expectRevert("ad is live");
        idx.prune(alice, 0);
        vm.warp(block.timestamp + 1 days);
        vm.prank(bob);
        idx.prune(alice, 0);
        assertEq(idx.count(DIRECTORY), 0);
        assertEq(idx.sequenceOf(alice, 0), 1, "pruning keeps the sequence");
    }

    function test_boundsOnSlotsEndpointsAndContent() public {
        vm.startPrank(alice);
        vm.expectRevert("slot out of range");
        idx.publish(8, DIRECTORY, 1, 1, exp(1 days), bytes32(0), eps("https://a.example"));
        vm.expectRevert("1 to 4 endpoints");
        idx.publish(0, DIRECTORY, 1, 1, exp(1 days), bytes32(0), new string[](0));
        string[] memory five = new string[](5);
        for (uint256 i = 0; i < 5; i++) five[i] = "https://a.example";
        vm.expectRevert("1 to 4 endpoints");
        idx.publish(0, DIRECTORY, 1, 1, exp(1 days), bytes32(0), five);
        vm.expectRevert("endpoint length");
        idx.publish(0, DIRECTORY, 1, 1, exp(1 days), bytes32(0), eps(string(new bytes(257))));
        vm.expectRevert("endpoint must be printable ASCII");
        idx.publish(0, DIRECTORY, 1, 1, exp(1 days), bytes32(0), eps("https://a.example/ x"));
        vm.expectRevert("kind and version required");
        idx.publish(0, 0, 1, 1, exp(1 days), bytes32(0), eps("https://a.example"));
        vm.stopPrank();
    }

    function test_pagesAreBounded() public {
        for (uint160 i = 1; i <= 70; i++) {
            vm.prank(address(i * 7919));
            idx.publish(0, DIRECTORY, 1, 1, exp(1 days), bytes32(0), eps("https://d.example"));
        }
        (EnclaveServiceIndex.Ad[] memory p, uint256 total) = idx.page(DIRECTORY, 0, 1000);
        assertEq(total, 70); assertEq(p.length, 64, "at most MAX_PAGE per call");
        (p, total) = idx.page(DIRECTORY, 64, 64);
        assertEq(p.length, 6);
        (p, total) = idx.page(DIRECTORY, 70, 64);
        assertEq(p.length, 0);
        // a withdrawal in the middle keeps the list dense (swap and pop)
        vm.prank(address(uint160(3 * 7919)));
        idx.withdraw(0, 2);
        assertEq(idx.count(DIRECTORY), 69);
        (p,) = idx.page(DIRECTORY, 0, 64);
        for (uint256 i = 0; i < p.length; i++) assertTrue(p[i].operator != address(0));
    }
}

/// A minimal smart-contract wallet: its owner executes calls from the wallet's address, and it answers ERC-1271 for
/// digests its owner signed. `mode` makes it misbehave for the refusal tests.
contract TestWallet {
    address public owner;
    uint8 public mode; // 0 honest, 1 revert, 2 wrong magic, 3 short answer, 4 burn gas
    constructor(address owner_) { owner = owner_; }
    function setMode(uint8 m) external { require(msg.sender == owner); mode = m; }
    function execute(address to, bytes calldata data) external returns (bytes memory r) {
        require(msg.sender == owner, "not owner");
        bool ok; (ok, r) = to.call(data);
        if (!ok) assembly { revert(add(r, 0x20), mload(r)) }
    }
    function isValidSignature(bytes32 digest, bytes calldata sig) external view returns (bytes4) {
        if (mode == 1) revert("no");
        if (mode == 2) return 0xdeadbeef;
        if (mode == 3) assembly { mstore(0, 0x1626ba7e00000000000000000000000000000000000000000000000000000000) return(0, 4) }
        if (mode == 4) { uint256 x; while (true) { x++; } }
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(digest, v, r, s) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

contract EnclaveServiceIndexWalletTest is Test {
    EnclaveServiceIndex idx;
    uint256 ownerKey = 0x0A11;
    address owner;
    TestWallet wallet;

    function setUp() public {
        vm.warp(1_800_000_000);
        idx = new EnclaveServiceIndex();
        owner = vm.addr(ownerKey);
        wallet = new TestWallet(owner);
    }
    function eps(string memory a) internal pure returns (string[] memory e) { e = new string[](1); e[0] = a; }
    function walletSig(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encode(r, s, v); // the wallet's own signature format (96 bytes), not an EOA signature
    }

    function test_walletPublishesByDirectCall() public {
        uint64 exp = uint64(block.timestamp + 1 days);
        vm.prank(owner);
        wallet.execute(address(idx), abi.encodeCall(idx.publish, (0, 1, 1, 1, exp, bytes32(0), eps("https://dir.wallet-ops.org"))));
        assertEq(idx.get(address(wallet), 0).operator, address(wallet));
        vm.prank(owner);
        wallet.execute(address(idx), abi.encodeCall(idx.withdraw, (0, 2)));
        assertEq(idx.get(address(wallet), 0).operator, address(0));
    }

    function test_walletSignedPublishIsSponsoredViaErc1271() public {
        uint64 exp = uint64(block.timestamp + 1 days);
        string[] memory e = eps("https://dir.wallet-ops.org");
        bytes32 d = idx.publishDigest(address(wallet), 0, 1, 1, 1, exp, bytes32(0), e);
        // a key that is not the wallet's owner
        bytes memory bad = walletSig(0xBAD, d);
        vm.expectRevert("not signed by operator");
        idx.publishFor(address(wallet), 0, 1, 1, 1, exp, bytes32(0), e, bad);
        // the owner's approval, through the wallet, submitted by anyone
        bytes memory good = walletSig(ownerKey, d);
        vm.prank(address(0xFEE));
        idx.publishFor(address(wallet), 0, 1, 1, 1, exp, bytes32(0), e, good);
        assertEq(idx.get(address(wallet), 0).operator, address(wallet));
        // the same approval cannot be replayed (sequence) nor used on another chain
        vm.expectRevert("stale sequence");
        idx.publishFor(address(wallet), 0, 1, 1, 1, exp, bytes32(0), e, good);
        bytes32 w = idx.withdrawDigest(address(wallet), 0, 2);
        bytes memory wsig = walletSig(ownerKey, w);
        vm.chainId(31338);
        vm.expectRevert("not signed by operator");
        idx.withdrawFor(address(wallet), 0, 2, wsig);
        vm.chainId(31337);
        idx.withdrawFor(address(wallet), 0, 2, wsig);
        assertEq(idx.get(address(wallet), 0).operator, address(0));
    }

    function test_misbehavingWalletsAreRefused() public {
        uint64 exp = uint64(block.timestamp + 1 days);
        string[] memory e = eps("https://dir.wallet-ops.org");
        bytes memory good = walletSig(ownerKey, idx.publishDigest(address(wallet), 0, 1, 1, 1, exp, bytes32(0), e));
        for (uint8 m = 1; m <= 4; m++) {
            vm.prank(owner); wallet.setMode(m);
            vm.expectRevert("not signed by operator");
            idx.publishFor{gas: 2_000_000}(address(wallet), 0, 1, 1, 1, exp, bytes32(0), e, good);
        }
        // an oversized signature is refused before the wallet is asked
        vm.prank(owner); wallet.setMode(0);
        vm.expectRevert("not signed by operator");
        idx.publishFor(address(wallet), 0, 1, 1, 1, exp, bytes32(0), e, new bytes(2049));
        // an EOA operator never gets the ERC-1271 path
        vm.expectRevert("not signed by operator");
        idx.publishFor(owner, 0, 1, 1, 1, exp, bytes32(0), e, good);
    }
}
