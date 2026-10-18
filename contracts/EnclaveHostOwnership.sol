// SPDX-License-Identifier: MIT
pragma solidity ^0.8.35;

interface IHostOwnershipRegistry {
    struct Entry {
        string endpoint;
        string repo;
        bytes32 measurement;
        address operator;
        uint64 registeredAt;
        uint64 lastSeen;
        bool active;
    }
    function get(bytes32 id) external view returns (Entry memory);
}

/// @notice Wallet authority over one host's local admission policy. No global
/// deployment veto or administrator. This does not use payout declarations.
/// The registered operator nominates the initial owner; that wallet accepts.
/// Subsequent transfers require the existing owner and the new owner.
contract EnclaveHostOwnership {
    IHostOwnershipRegistry public immutable registry;
    struct Authority {
        address owner;
        address pendingOwner;
        uint64 revision;
        bytes32 policyHash;
    }
    mapping(bytes32 => Authority) public authority;
    event OwnerProposed(bytes32 indexed hostId, address indexed owner);
    event OwnerAccepted(bytes32 indexed hostId, address indexed owner, uint64 revision);
    event PolicySet(bytes32 indexed hostId, uint64 revision, bytes32 policyHash);

    constructor(address registry_) {
        require(registry_.code.length != 0, "registry required");
        registry = IHostOwnershipRegistry(registry_);
    }
    function proposeOwner(bytes32 hostId, address next) external {
        require(next != address(0), "owner required");
        Authority storage a = authority[hostId];
        if (a.owner == address(0)) {
            IHostOwnershipRegistry.Entry memory e = registry.get(hostId);
            require(e.active && e.operator == msg.sender, "not active operator");
        } else {
            require(a.owner == msg.sender, "not owner");
        }
        a.pendingOwner = next;
        emit OwnerProposed(hostId, next);
    }
    function cancelProposal(bytes32 hostId) external {
        Authority storage a = authority[hostId];
        if (a.owner == address(0)) {
            IHostOwnershipRegistry.Entry memory e = registry.get(hostId);
            require(e.operator == msg.sender, "not operator");
        } else require(a.owner == msg.sender, "not owner");
        a.pendingOwner = address(0);
        emit OwnerProposed(hostId, address(0));
    }
    function acceptOwner(bytes32 hostId) external {
        Authority storage a = authority[hostId];
        require(a.pendingOwner == msg.sender, "not proposed owner");
        a.owner = msg.sender;
        a.pendingOwner = address(0);
        // A former owner's policy cannot constrain the new owner's host.
        a.policyHash = bytes32(0);
        a.revision++;
        emit OwnerAccepted(hostId, msg.sender, a.revision);
    }
    function setPolicy(bytes32 hostId, bytes32 policyHash) external {
        Authority storage a = authority[hostId];
        require(a.owner == msg.sender, "not owner");
        a.policyHash = policyHash;
        a.revision++;
        emit PolicySet(hostId, a.revision, policyHash);
    }
}
