// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ISealableGovernance {
    function owner() external view returns (address);
    function pendingOwner() external view returns (address);
    function acceptOwnership() external;
}

/// Irreversibly holds a reviewed contract's administrative ownership. There is
/// no forwarding, upgrade, owner, recovery or withdrawal function. Deployment
/// alone changes nothing: the target's current owner must explicitly nominate
/// this address, after which anyone can finalize the exact reviewed configuration.
///
/// This does NOT remove authority in proxy implementations or dependencies.
/// Use only for reviewed immutable target bytecode, with a complete getter set.
/// Token holders and deployment owners retain their target-contract permissions.
contract GovernanceSeal {
    address public immutable target;
    bytes32 public immutable targetCodeHash;
    bytes32 public immutable configurationHash;
    bytes4[] private _selectors;
    bool public isSealed;

    event GovernanceSealed(address indexed target, bytes32 codeHash, bytes32 configurationHash);

    constructor(address target_, bytes4[] memory selectors, bytes32 expectedConfigurationHash) {
        require(target_.code.length != 0, "target code missing");
        require(selectors.length != 0 && selectors.length <= 64, "getter count");
        target = target_;
        targetCodeHash = target_.codehash;
        for (uint256 i; i < selectors.length; ++i) {
            require(selectors[i] != ISealableGovernance.owner.selector &&
                selectors[i] != ISealableGovernance.pendingOwner.selector, "ownership is not configuration");
            for (uint256 j; j < i; ++j) require(selectors[i] != selectors[j], "duplicate getter");
            _selectors.push(selectors[i]);
        }
        configurationHash = expectedConfigurationHash;
        require(currentConfigurationHash() == expectedConfigurationHash, "configuration changed");
    }

    function selectors() external view returns (bytes4[] memory) { return _selectors; }

    /// Commit to chain, address, bytecode, ordered getter selectors and their ABI
    /// encoded responses. Rechecked immediately before accepting ownership.
    function currentConfigurationHash() public view returns (bytes32 hash) {
        hash = keccak256(abi.encode(block.chainid, target, targetCodeHash));
        for (uint256 i; i < _selectors.length; ++i) {
            (bool ok, bytes memory value) = target.staticcall(abi.encodePacked(_selectors[i]));
            require(ok && value.length != 0 && value.length <= 1024, "getter failed");
            hash = keccak256(abi.encode(hash, _selectors[i], keccak256(value)));
        }
    }

    function seal() external {
        require(!isSealed, "already sealed");
        require(target.codehash == targetCodeHash, "target code changed");
        require(currentConfigurationHash() == configurationHash, "configuration changed");
        require(ISealableGovernance(target).pendingOwner() == address(this), "not nominated");
        isSealed = true;
        ISealableGovernance(target).acceptOwnership();
        require(ISealableGovernance(target).owner() == address(this), "ownership not accepted");
        emit GovernanceSealed(target, targetCodeHash, configurationHash);
    }
}
