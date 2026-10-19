//go:build !bootstrapportlab

package main

// Transport ports are measured constants, never supplied by the host at boot.
func directPorts() (egress, custody, pkg uint32) { return 9443, 9445, 9446 }
