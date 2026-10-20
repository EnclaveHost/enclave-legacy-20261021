// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {GovernanceSealHostingTest} from "./GovernanceSeal.hosting.t.sol";
import {EnclaveDeployments} from "../../EnclaveDeployments.sol";
import {EnclaveRegistry} from "../../EnclaveRegistry.sol";
import {EnclaveProofOfTime} from "../../EnclaveProofOfTime.sol";
import {MockUSDC} from "./mocks/MockUSDC.sol";

/// Opt-in Base fork. No broadcast/wallet; writes exist only in Forge's local
/// simulation. Skip on the default test chain rather than claiming a live test.
contract GovernanceSealLiveForkTest is GovernanceSealHostingTest {
    function setUp() public override {
        vm.skip(block.chainid != 8453);
        ledger = EnclaveDeployments(0xB1783B61E1FDee6a6163DC3CdaC27bF32E7d117B);
        registry = EnclaveRegistry(address(ledger.registry()));
        proof = EnclaveProofOfTime(ledger.prover());
        usdc = MockUSDC(address(ledger.usdc())); // ERC20 surface only; no mock mint
        assertEq(ledger.deploymentsSchema(),16);
        assertTrue(ledger.importsSealed()); assertFalse(ledger.retired());
        assertEq(proof.owner(),ledger.owner());
        assertEq(address(proof.deployments()),address(ledger));
        formerGovernor = ledger.owner();
        vm.startPrank(formerGovernor); _sealLedgerAndProof(); vm.stopPrank();
        deal(address(usdc),tenant,100e6);
        vm.prank(tenant); usdc.approve(address(ledger),type(uint256).max);
        vm.warp(T0); vm.roll(1000);
    }
}
