//go:build bootstrapportlab && bootstrapdirect && !releaselab

package main

// The hardware lab uses the production chain, TLS roots and authorization.
// Only its host transport ports differ, allowing a separate guestd to coexist
// with production guests. This is a distinct measured release.
func directPorts() (egress, custody, pkg uint32) { return 19443, 19445, 19446 }
