//go:build windows

package main

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// writeAccessMask is every access right that lets a trustee modify the
// object's own data, attributes, or its security itself. Read-only access
// (FILE_READ_DATA, FILE_LIST_DIRECTORY, ...) is not a tampering risk and is
// deliberately left out, matching the reasoning validateKnownHostsPath
// already applies on Unix (rejecting group/other WRITE, not mere
// readability).
const writeAccessMask = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
	windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.DELETE |
	windows.GENERIC_WRITE | windows.GENERIC_ALL

func validateKnownHostsDir(path string) error {
	return validateKnownHostsPathWindows(path, true)
}

func validateKnownHostsFile(path string) error {
	return validateKnownHostsPathWindows(path, false)
}

// validateKnownHostsPathWindows is the Windows counterpart of Unix's
// validateKnownHostsPath (N9): a symlink or reparse point/junction is
// refused outright, the object type must match what's expected, the owner
// must be the current user (or Administrators/SYSTEM -- see
// trustedOwnerSIDs), and the DACL must not grant a write-capable access
// right to any other trustee. Unlike Unix mode bits, an ACL can grant
// tampering rights to an arbitrary set of principals, so this walks every
// ACE rather than checking a single set of permission bits.
func validateKnownHostsPathWindows(path string, wantDir bool) error {
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("checking known_hosts security for %s: %w", path, err)
	}
	attrs, err := windows.GetFileAttributes(pathp)
	if err != nil {
		return fmt.Errorf("checking known_hosts security for %s: %w", path, err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refusing insecure known_hosts path %s: reparse points (symlinks/junctions) are not allowed", path)
	}
	isDir := attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if wantDir != isDir {
		kind := "file"
		if wantDir {
			kind = "directory"
		}
		return fmt.Errorf("refusing insecure known_hosts path %s: expected a %s", path, kind)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("checking known_hosts security for %s: %w", path, err)
	}

	trusted, err := trustedOwnerSIDs()
	if err != nil {
		return fmt.Errorf("checking known_hosts ownership for %s: %w", path, err)
	}

	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("checking known_hosts ownership for %s: %w", path, err)
	}
	if !sidIn(owner, trusted) {
		return fmt.Errorf("refusing insecure known_hosts path %s: not owned by the current user, Administrators, or SYSTEM", path)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
			// A security descriptor with no DACL at all means "everyone has
			// full access" -- the least secure state it can be in.
			return fmt.Errorf("refusing insecure known_hosts path %s: no discretionary access control list is present (everyone has full access)", path)
		}
		return fmt.Errorf("checking known_hosts permissions for %s: %w", path, err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("checking known_hosts permissions for %s: %w", path, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue // only an explicit ALLOW can actually grant access
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue // doesn't apply to this object itself, only to children
		}
		if ace.Mask&writeAccessMask == 0 {
			continue
		}
		// ACCESS_ALLOWED_ACE.SidStart is a placeholder marking where the
		// variable-length SID data actually begins in memory, the standard
		// Win32 ACE layout (see the struct's own doc comment/MSDN).
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sidIn(sid, trusted) {
			continue
		}
		return fmt.Errorf("refusing insecure known_hosts path %s: grants write access to a trustee other than the current user, Administrators, or SYSTEM", path)
	}
	return nil
}

// trustedOwnerSIDs returns the current user's SID plus the well-known
// Administrators and SYSTEM SIDs -- a file legitimately created by an
// elevated process, an admin-run installer, or the OS itself is commonly
// owned by one of those instead of the interactive user, the same
// convention OpenSSH for Windows uses for its own StrictModes-equivalent
// checks.
func trustedOwnerSIDs() ([]*windows.SID, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, err
	}
	defer token.Close()
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{tokenUser.User.Sid, admins, system}, nil
}

func sidIn(sid *windows.SID, set []*windows.SID) bool {
	for _, s := range set {
		if sid.Equals(s) {
			return true
		}
	}
	return false
}
