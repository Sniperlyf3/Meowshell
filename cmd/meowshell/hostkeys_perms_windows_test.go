//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// currentUserSID mirrors the lookup trustedOwnerSIDs itself does, for a test
// to build an ACL naming the current user explicitly.
func currentUserSID(t *testing.T) *windows.SID {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatalf("OpenCurrentProcessToken: %v", err)
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	sid, err := tokenUser.User.Sid.Copy()
	if err != nil {
		t.Fatalf("copying the current user's SID: %v", err)
	}
	return sid
}

// setDACL replaces path's DACL outright (PROTECTED_DACL_SECURITY_INFORMATION
// stops any inherited ACEs from a parent directory -- e.g. %TEMP%'s own DACL
// -- from being merged back in, so the test's ACL is exactly what it set).
func setDACL(t *testing.T, path string, entries []windows.EXPLICIT_ACCESS) {
	t.Helper()
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatalf("ACLFromEntries: %v", err)
	}
	err = windows.SetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil)
	if err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
}

func grantSID(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// TestValidateKnownHostsFileAcceptsAnOwnerOnlyDACL is the Windows
// counterpart of the Unix "explicit chmod 0600 is accepted" baseline: a
// DACL granting only the current user access must pass.
func TestValidateKnownHostsFileAcceptsAnOwnerOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, []windows.EXPLICIT_ACCESS{grantSID(currentUserSID(t), windows.GENERIC_ALL)})

	if err := validateKnownHostsFile(path); err != nil {
		t.Errorf("validateKnownHostsFile with an owner-only DACL = %v, want nil", err)
	}
}

// TestValidateKnownHostsFileRejectsAWorldWritableDACL is the Windows
// counterpart of Unix's TestTCPHostKeyCallbackRejectsInsecureKnownHostsFile:
// a DACL that additionally grants write access to Everyone (S-1-1-0) must be
// refused, mirroring OpenSSH-for-Windows' own StrictModes-equivalent check.
func TestValidateKnownHostsFileRejectsAWorldWritableDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(WinWorldSid): %v", err)
	}
	setDACL(t, path, []windows.EXPLICIT_ACCESS{
		grantSID(currentUserSID(t), windows.GENERIC_ALL),
		grantSID(everyone, windows.GENERIC_WRITE),
	})

	err = validateKnownHostsFile(path)
	if err == nil || !strings.Contains(err.Error(), "write access") {
		t.Fatalf("validateKnownHostsFile with a world-writable DACL = %v, want a write-access rejection", err)
	}
}

// TestValidateKnownHostsFileAcceptsWorldReadOnlyDACL confirms read-only
// access for another trustee is fine -- only write-capable rights are a
// tampering risk, the same distinction Unix's own check makes (rejecting
// group/other WRITE, not mere readability).
func TestValidateKnownHostsFileAcceptsWorldReadOnlyDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	everyone, err := windows.CreateWellKnownSid(windows.WinWorldSid)
	if err != nil {
		t.Fatalf("CreateWellKnownSid(WinWorldSid): %v", err)
	}
	setDACL(t, path, []windows.EXPLICIT_ACCESS{
		grantSID(currentUserSID(t), windows.GENERIC_ALL),
		grantSID(everyone, windows.GENERIC_READ),
	})

	if err := validateKnownHostsFile(path); err != nil {
		t.Errorf("validateKnownHostsFile with a world-readable (not writable) DACL = %v, want nil", err)
	}
}

func TestValidateKnownHostsDirRejectsAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, path, []windows.EXPLICIT_ACCESS{grantSID(currentUserSID(t), windows.GENERIC_ALL)})

	err := validateKnownHostsDir(path)
	if err == nil || !strings.Contains(err.Error(), "expected a directory") {
		t.Fatalf("validateKnownHostsDir on a file = %v, want an object-type rejection", err)
	}
}

func TestValidateKnownHostsFileRejectsADirectory(t *testing.T) {
	dir := t.TempDir()
	setDACL(t, dir, []windows.EXPLICIT_ACCESS{grantSID(currentUserSID(t), windows.GENERIC_ALL)})

	err := validateKnownHostsFile(dir)
	if err == nil || !strings.Contains(err.Error(), "expected a file") {
		t.Fatalf("validateKnownHostsFile on a directory = %v, want an object-type rejection", err)
	}
}

// TestValidateKnownHostsFileRejectsASymlink is the Windows counterpart of
// Unix's TestTCPHostKeyCallbackRejectsSymlinkedKnownHostsFile. Symlink
// creation on Windows needs either Developer Mode or an elevated process
// (SeCreateSymbolicLinkPrivilege); skip rather than fail if this environment
// doesn't allow it.
func TestValidateKnownHostsFileRejectsASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setDACL(t, target, []windows.EXPLICIT_ACCESS{grantSID(currentUserSID(t), windows.GENERIC_ALL)})

	path := filepath.Join(dir, "known_hosts")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("creating a symlink is not permitted in this environment: %v", err)
	}

	err := validateKnownHostsFile(path)
	if err == nil || !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("validateKnownHostsFile on a symlink = %v, want a reparse-point rejection", err)
	}
}
