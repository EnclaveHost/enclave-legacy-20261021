// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;
import "forge-std/Test.sol";
import "../../EnclaveHostOwnership.sol";
import "../../EnclaveRegistry.sol";
contract HostOwnershipTest is Test {
    EnclaveRegistry registry;
    EnclaveHostOwnership ownership;
    address operator = address(0x1234);
    address owner = address(0x2345);
    address buyer = address(0x3456);
    bytes32 host;
    function setUp() public {
        registry = new EnclaveRegistry();
        ownership = new EnclaveHostOwnership(address(registry));
        vm.prank(operator);
        host = registry.register("https://host.example", "source", bytes32(0), 1, 0, address(0));
    }
    function claim() internal {
        vm.prank(operator); ownership.proposeOwner(host, owner);
        vm.prank(owner); ownership.acceptOwner(host);
    }
    function testBothOperatorAndWalletMustConsent() public {
        vm.expectRevert("not active operator"); vm.prank(owner); ownership.proposeOwner(host, owner);
        vm.prank(operator); ownership.proposeOwner(host, owner);
        vm.expectRevert("not proposed owner"); vm.prank(operator); ownership.acceptOwner(host);
        vm.prank(owner); ownership.acceptOwner(host);
        (address current,,uint64 revision,)=ownership.authority(host);
        assertEq(current,owner);assertEq(revision,1);
    }
    function testPayoutDeclarationCannotGrantVetoOrTransfer() public {
        claim();
        vm.prank(buyer);registry.setPayoutWallet(host);
        vm.expectRevert("not owner");vm.prank(buyer);ownership.setPolicy(host,bytes32(uint256(1)));
        vm.expectRevert("not owner");vm.prank(operator);ownership.proposeOwner(host,buyer);
        (address current,,,)=ownership.authority(host);assertEq(current,owner);
    }
    function testTransferRevokesOldOwnerAndPolicy() public {
        claim();vm.prank(owner);ownership.setPolicy(host,bytes32(uint256(1)));
        vm.prank(owner);ownership.proposeOwner(host,buyer);
        (address current,,,bytes32 policy)=ownership.authority(host);assertEq(current,owner);assertEq(policy,bytes32(uint256(1)));
        vm.prank(buyer);ownership.acceptOwner(host);
        uint64 revision;
        (current,,revision,policy)=ownership.authority(host);
        assertEq(current,buyer);assertEq(revision,3);assertEq(policy,bytes32(0));
        vm.expectRevert("not owner");vm.prank(owner);ownership.setPolicy(host,bytes32(uint256(2)));
    }
    function testPolicyCannotAffectAnotherHost() public {
        claim();bytes32 other=keccak256("other");
        vm.expectRevert("not owner");vm.prank(owner);ownership.setPolicy(other,bytes32(uint256(1)));
        vm.prank(owner);ownership.setPolicy(host,bytes32(uint256(1)));
        (,,,bytes32 policy)=ownership.authority(other);assertEq(policy,bytes32(0));
    }
}
