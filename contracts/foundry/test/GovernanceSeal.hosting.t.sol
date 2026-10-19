// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {EnclaveDeployments} from "../../EnclaveDeployments.sol";
import {EnclaveRegistry} from "../../EnclaveRegistry.sol";
import {EnclaveProofOfTime} from "../../EnclaveProofOfTime.sol";
import {GovernanceSeal} from "../../GovernanceSeal.sol";
import {MockUSDC} from "./mocks/MockUSDC.sol";

/// Real ledger, registry and proof verifier. Only the token and attested key
/// are test fixtures: this proves contract behavior, not a live independent TEE.
contract GovernanceSealHostingTest is Test {
    uint256 constant T0 = 1_800_000_000;
    uint256 constant PROOF_KEY = 0xB0B;
    EnclaveDeployments ledger;
    EnclaveRegistry registry;
    EnclaveProofOfTime proof;
    MockUSDC usdc;
    address tenant = makeAddr("new independent tenant");
    address operator = makeAddr("independent runner");
    address gasPayer = makeAddr("independent proof submitter");
    address treasury = makeAddr("treasury");
    address formerGovernor;

    function _seal(address target, string[] memory names) internal returns(GovernanceSeal s) {
        bytes4[] memory selectors = new bytes4[](names.length);
        bytes32 hash = keccak256(abi.encode(block.chainid,target,target.codehash));
        for(uint256 i; i < names.length; ++i) {
            selectors[i] = bytes4(keccak256(bytes(names[i])));
            (bool ok,bytes memory result) = target.staticcall(abi.encodePacked(selectors[i]));
            require(ok);
            hash = keccak256(abi.encode(hash,selectors[i],keccak256(result)));
        }
        s = new GovernanceSeal(target,selectors,hash);
    }

    function setUp() public virtual {
        vm.warp(T0); vm.roll(1000);
        usdc = new MockUSDC(); registry = new EnclaveRegistry();
        ledger = new EnclaveDeployments(address(usdc),treasury,address(registry),address(0));
        formerGovernor = ledger.owner();
        proof = new EnclaveProofOfTime(address(ledger),address(registry));
        ledger.setProver(address(proof)); ledger.setProofRequiredFrom(uint64(T0)); ledger.sealImports();
        _sealLedgerAndProof();
        usdc.mint(tenant,100e6);
        vm.prank(tenant); usdc.approve(address(ledger),type(uint256).max);
    }

    function _sealLedgerAndProof() internal {
        string[] memory getters = new string[](17);
        getters[0]="deploymentsSchema()"; getters[1]="retired()"; getters[2]="importsSealed()";
        getters[3]="usdc()"; getters[4]="registry()"; getters[5]="payout()"; getters[6]="ethUsdFeed()";
        getters[7]="leaseSec()"; getters[8]="maxGpuMilli()"; getters[9]="maxFeePerSec6()";
        getters[10]="runnerBps()"; getters[11]="claimBond6()"; getters[12]="bondExitDelay()";
        getters[13]="prover()"; getters[14]="proofRequiredFrom()"; getters[15]="feeRouter()";
        getters[16]="bandwidthRouter()";
        GovernanceSeal ledgerSeal = _seal(address(ledger),getters);
        ledger.setOwner(address(ledgerSeal)); ledgerSeal.seal();
        getters = new string[](4);
        getters[0]="proofSchema()"; getters[1]="deployments()"; getters[2]="registry()"; getters[3]="proofWindowSec()";
        GovernanceSeal proofSeal = _seal(address(proof),getters);
        proof.transferOwnership(address(proofSeal)); proofSeal.seal();
    }

    function test_independentRegistrationClaimProofRenewAndOwnerStopSurviveSealing() public {
        // All role registration and work creation happen AFTER the former
        // governance wallet has lost authority, with no catalog approval/API.
        vm.prank(operator);
        bytes32 host = registry.register("https://independent.example","publisher/runtime",bytes32(uint256(42)),1000,0,vm.addr(PROOF_KEY));
        vm.startPrank(tenant);
        bytes32 id = ledger.create("catalog://explicit-release/0",0,100,8080,"",true,"",address(0),0,1000);
        ledger.fund(id,10e6); usdc.transfer(operator,1e6); vm.stopPrank();
        vm.startPrank(operator);
        usdc.approve(address(ledger),1e6); ledger.postBond(1e6);
        vm.stopPrank();
        vm.prank(operator); ledger.claim(id,host);
        uint64 originalLease = ledger.get(id).leaseUntil;
        assertTrue(ledger.proofRequired());

        vm.startPrank(formerGovernor);
        vm.expectRevert(); ledger.retire();
        vm.expectRevert(); ledger.setMaxGpuMilli(0);
        vm.expectRevert(); ledger.setClaimBond(1_000_000e6,1 days);
        vm.expectRevert(); ledger.slashBond(operator,1,"refuses Enclave policy");
        vm.expectRevert(); proof.setProofWindow(60);
        vm.expectRevert(); registry.deregister(host);
        vm.stopPrank();

        vm.warp(T0+300); vm.roll(1150);
        bytes32 anchor = keccak256("independent chain block"); vm.setBlockhash(1149,anchor);
        bytes32 digest = proof.proofDigest(id,host,operator,uint64(T0+300),1149,anchor);
        (uint8 v,bytes32 r,bytes32 s) = vm.sign(PROOF_KEY,digest);
        vm.prank(gasPayer); proof.checkpoint(id,host,uint64(T0+300),1149,anchor,abi.encodePacked(r,s,v));
        vm.prank(operator); ledger.renew(id);
        assertGt(ledger.get(id).leaseUntil,originalLease);
        assertGt(ledger.earned6(operator),0);
        vm.prank(operator); ledger.withdrawEarnings(operator);
        assertGt(usdc.balanceOf(operator),0);

        // Governance removal must not remove the tenant's authority.
        vm.prank(tenant); ledger.setActive(id,false);
        vm.prank(operator); vm.expectRevert(); ledger.renew(id);
        vm.prank(operator); ledger.release(id);
        uint256 before = usdc.balanceOf(tenant);
        vm.prank(tenant); ledger.refund(id);
        assertGt(usdc.balanceOf(tenant),before);
        vm.prank(tenant); ledger.transferDeployment(id,gasPayer);
        vm.prank(tenant); vm.expectRevert(); ledger.setActive(id,true);
        vm.prank(gasPayer); ledger.setActive(id,true);
        assertEq(ledger.get(id).owner,gasPayer);
        vm.prank(operator); ledger.requestBondExit();
        vm.warp(T0+300+1 days);
        uint256 operatorBefore = usdc.balanceOf(operator);
        vm.prank(operator); ledger.withdrawBond(operator);
        assertEq(usdc.balanceOf(operator),operatorBefore+1e6);
    }
}
