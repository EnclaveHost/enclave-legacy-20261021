//go:build bootstrapdirect && !releaselab

package main

// A distinct measured binary; no flag, host request, timeout or release failure
// may switch a legacy guest onto this path.
const directBootstrap = true
