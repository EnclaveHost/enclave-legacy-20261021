// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { SessionRig } from "./SessionVault.t.sol";
import { GovernanceSeal } from "../../GovernanceSeal.sol";

contract GovernanceSealTest is SessionRig {
    function snapshot(address target, bytes4[] memory selectors) internal view returns (bytes32 h) {
        h = keccak256(abi.encode(block.chainid, target, target.codehash));
        for (uint256 i; i < selectors.length; ++i) {
            (bool ok, bytes memory value) = target.staticcall(abi.encodePacked(selectors[i]));
            require(ok);
            h = keccak256(abi.encode(h, selectors[i], keccak256(value)));
        }
    }

    // Test profile, not a production review manifest. Production must cover all
    // admin-mutable settings and dependency bindings of the deployed revision.
    function makeSeal() internal returns (GovernanceSeal s) {
        bytes4[] memory getters = new bytes4[](5);
        getters[0] = bytes4(keccak256("retired()"));
        getters[1] = bytes4(keccak256("importsSealed()"));
        getters[2] = bytes4(keccak256("leaseSec()"));
        getters[3] = bytes4(keccak256("claimBond6()"));
        getters[4] = bytes4(keccak256("proofRequiredFrom()"));
        ledger.sealImports();
        s = new GovernanceSeal(address(ledger), getters, snapshot(address(ledger), getters));
    }

    function test_deploymentAloneCannotAcquireAuthority() public {
        GovernanceSeal s = makeSeal();
        assertEq(ledger.owner(), address(this));
        vm.expectRevert(bytes("not nominated")); s.seal();
        assertFalse(s.isSealed());
    }

    function test_nominationCanBeCancelledBeforeAcceptance() public {
        GovernanceSeal s = makeSeal();
        ledger.setOwner(address(s));
        ledger.setOwner(relayer);
        vm.expectRevert(bytes("not nominated")); s.seal();
        assertEq(ledger.owner(), address(this));
    }

    function test_configurationDriftRefusesOwnershipTransfer() public {
        GovernanceSeal s = makeSeal();
        ledger.setOwner(address(s));
        ledger.setLeaseSec(3600);
        vm.expectRevert(bytes("configuration changed")); s.seal();
        assertEq(ledger.owner(), address(this));
        assertFalse(s.isSealed());
    }

    function test_codeReplacementRefusesOwnershipTransfer() public {
        GovernanceSeal s = makeSeal();
        ledger.setOwner(address(s));
        vm.etch(address(ledger), hex"00");
        vm.expectRevert(bytes("target code changed")); s.seal();
    }

    function test_sealedLedgerAcceptsFundedDeploymentsAndOwnerRefunds() public {
        GovernanceSeal s = makeSeal();
        ledger.setOwner(address(s));
        vm.prank(relayer); s.seal(); // no privileged finalizer
        assertEq(ledger.owner(), address(s));
        assertTrue(s.isSealed());
        vm.expectRevert(); ledger.retire();
        vm.expectRevert(); ledger.setClaimBond(1000e6, 1 days);
        vm.expectRevert(); ledger.setOwner(address(this));
        (bool ok,) = address(s).call(abi.encodeWithSignature("execute(address,bytes)", address(ledger), abi.encodeWithSignature("retire()")));
        assertFalse(ok);
        vm.expectRevert(bytes("already sealed")); s.seal();
        bytes32 sid = _openWithDeposit(_grant(keyHash, 2e6));
        bytes32 id = abi.decode(_exec(sid, 0, 0, _createArgs(freeRef, 1, 1e6), 0), (bytes32));
        assertEq(ledger.get(id).balance6, 1e6);
        assertFalse(ledger.retired());
        uint256 before = usdc.balanceOf(address(vault));
        uint256 refundable = ledger.refundableOf(id);
        assertGt(refundable, 0);
        vm.prank(address(vault)); ledger.refund(id);
        assertEq(usdc.balanceOf(address(vault)), before + refundable);
    }

    function test_badManifestCannotCreateSeal() public {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = bytes4(keccak256("retired()"));
        vm.expectRevert(bytes("configuration changed"));
        new GovernanceSeal(address(ledger), selectors, bytes32(0));
        selectors[0] = bytes4(keccak256("owner()"));
        vm.expectRevert(bytes("ownership is not configuration"));
        new GovernanceSeal(address(ledger), selectors, bytes32(0));
    }
}
