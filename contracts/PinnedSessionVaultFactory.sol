// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { SessionVaultFactory, ISVToken, ISVBook, ISVRouter, ISVKeyAttestations } from "./SessionVault.sol";

/// Fixed bindings for a session deployment. There is no owner, setter, proxy,
/// delegatecall or mutable discovery fallback. The factory pins itself so the
/// legacy vault interface remains usable without a privileged directory.
contract PinnedSessionAuthority is ISVBook {
    address public immutable deployments;
    address public immutable appCatalog;
    address public immutable sessionVaultFactory;

    constructor(address ledger, address catalog, address factory) {
        require(ledger.code.length != 0 && catalog.code.length != 0, "authority code missing");
        require(factory != address(0), "factory missing");
        deployments = ledger;
        appCatalog = catalog;
        sessionVaultFactory = factory;
    }

    function addr(bytes32 name) external view returns (address) {
        if (name == bytes32("deployments")) return deployments;
        if (name == bytes32("appCatalog")) return appCatalog;
        if (name == bytes32("sessionVaultFactory")) return sessionVaultFactory;
        return address(0);
    }
}

/// Same session/clone protocol as SessionVaultFactory, with a private immutable
/// authority directory created in this constructor. Existing vaults are not
/// upgraded or moved; their owners must explicitly authorize any migration.
/// Pinning addresses does not remove governance inside the selected contracts.
contract PinnedSessionVaultFactory is SessionVaultFactory {
    constructor(ISVToken usdc, address ledger, address catalog, ISVRouter router,
        ISVKeyAttestations keyAttestations, uint256 maxVault6)
        SessionVaultFactory(usdc,
            ISVBook(address(new PinnedSessionAuthority(ledger, catalog, address(this)))),
            router, keyAttestations, maxVault6) {}

    function authorityPins() external view returns (address ledger, address catalog, address authority) {
        PinnedSessionAuthority pins = PinnedSessionAuthority(address(implementation.book()));
        return (pins.deployments(), pins.appCatalog(), address(pins));
    }
}
