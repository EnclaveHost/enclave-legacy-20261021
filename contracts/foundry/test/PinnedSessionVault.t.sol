// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { SessionRig } from "./SessionVault.t.sol";
import { SessionVault, SessionVaultFactory, ISVToken, ISVRouter, ISVKeyAttestations } from "../../SessionVault.sol";
import { PinnedSessionVaultFactory, PinnedSessionAuthority } from "../../PinnedSessionVaultFactory.sol";

contract PinnedSessionVaultTest is SessionRig {
    PinnedSessionVaultFactory pinned;

    function setUp() public override {
        super.setUp();
        pinned = new PinnedSessionVaultFactory(ISVToken(address(usdc)), address(ledger), address(catalog),
            ISVRouter(address(router)), ISVKeyAttestations(address(0)), 1_000e6);
        factory = SessionVaultFactory(address(pinned));
        vault = SessionVault(factory.vaultFor(owner));
    }

    function test_fixedBindingsAndDeterministicOwnerVault() public {
        (address l, address c, address a) = pinned.authorityPins();
        assertEq(l, address(ledger)); assertEq(c, address(catalog));
        assertEq(PinnedSessionAuthority(a).sessionVaultFactory(), address(pinned));
        assertEq(PinnedSessionAuthority(a).addr(bytes32("unconfigured")), address(0));
        address expected = factory.vaultFor(owner);
        vm.prank(relayer); assertEq(factory.createVault(owner), expected);
        assertEq(factory.createVault(owner), expected);
        assertEq(vault.owner(), owner);
        assertEq(address(vault.book()), a);
        assertTrue(factory.isVault(expected));
        assertLe(address(factory.implementation()).code.length, 24_576);
        assertLe(address(factory).code.length, 24_576);
    }

    function test_oldBookRemovalDoesNotStopNewSessionOrDeployment() public {
        book.set("deployments", address(0));
        book.set("appCatalog", address(0));
        book.set("sessionVaultFactory", address(0));
        bytes32 sid = _openWithDeposit(_grant(keyHash, 10e6));
        bytes32 id = abi.decode(_exec(sid, 0, 0, _createArgs(freeRef, 1, 1e6), 0), (bytes32));
        assertEq(ledger.get(id).owner, address(vault));
        assertEq(ledger.get(id).balance6, 1e6);
    }

    function test_oldBookRedirectionCannotRedirectSessionFunds() public {
        address hostile = makeAddr("hostile-ledger");
        book.set("deployments", hostile);
        book.set("appCatalog", hostile);
        book.set("sessionVaultFactory", hostile);
        bytes32 sid = _openWithDeposit(_grant(keyHash, 10e6));
        bytes32 id = abi.decode(_exec(sid, 0, 0, _createArgs(freeRef, 1, 1e6), 0), (bytes32));
        assertEq(ledger.get(id).balance6, 1e6);
        assertEq(usdc.balanceOf(hostile), 0);
        assertEq(usdc.allowance(address(vault), hostile), 0);
    }

    function test_catalogModerationDoesNotVetoExplicitSessionRelease() public {
        catalog.setApproval(freeAppId, 0, 2);
        bytes32 sid = _openWithDeposit(_grant(keyHash, 10e6));
        bytes32 id = abi.decode(_exec(sid, 0, 0, _createArgs(freeRef, 1, 1e6), 0), (bytes32));
        assertEq(ledger.get(id).appRef, freeRef);
    }

    function test_noAuthoritySetterOrAdministrator() public {
        (, , address authority) = pinned.authorityPins();
        (bool ok,) = authority.call(abi.encodeWithSignature("set(bytes32,address)", bytes32("deployments"), address(this)));
        assertFalse(ok);
        (ok,) = authority.call(abi.encodeWithSignature("setOwner(address)", address(this)));
        assertFalse(ok);
        (address l,,) = pinned.authorityPins(); assertEq(l, address(ledger));
    }

    function test_ownerRevocationAndBudgetSurviveDirectoryLoss() public {
        bytes32 sid = _openWithDeposit(_grant(keyHash, 1e6));
        book.set("deployments", address(0));
        _execExpectRevert(sid, 0, 0, _createArgs(freeRef, 1, 2e6), 0,
            abi.encodeWithSelector(SessionVault.BudgetExceeded.selector, uint256(2e6), uint256(1e6)));
        assertEq(ledger.count(), 0, "over-budget create must roll back");
        uint256 before = usdc.balanceOf(owner);
        vm.prank(owner); vault.revokeAll(true, bytes32(0), 0, "");
        assertEq(usdc.balanceOf(owner), before + 1e6);
        assertFalse(vault.isLive(sid));
        _execExpectRevert(sid, 0, 0, _createArgs(freeRef, 1, 0), 0,
            abi.encodeWithSelector(SessionVault.NotLive.selector));
    }

    function test_unauthorizedCallerCannotRevokeOrOpenOwnerSession() public {
        bytes32 sid = _openWithDeposit(_grant(keyHash, 1e6));
        vm.prank(relayer); vm.expectRevert(); vault.revokeAll(true, bytes32(0), 0, "");
        assertTrue(vault.isLive(sid));
        SessionVault.Grant memory grant = _grant(keccak256("other-session-key"), 0);
        vm.expectRevert(SessionVault.BadSignature.selector);
        factory.openFor(owner, grant, hex"01");
    }

    function test_refusesMissingAuthorityCode() public {
        vm.expectRevert(bytes("authority code missing"));
        new PinnedSessionVaultFactory(ISVToken(address(usdc)), address(0), address(catalog),
            ISVRouter(address(router)), ISVKeyAttestations(address(0)), 1_000e6);
    }
}
