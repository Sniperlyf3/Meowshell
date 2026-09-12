//go:build windows

package main

// withRestrictedUmask is a no-op on Windows: there is no umask concept, and
// Unix domain socket permission semantics don't apply the same way.
func withRestrictedUmask(fn func() error) error {
	return fn()
}
