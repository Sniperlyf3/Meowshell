// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build android

package main

import (
	"github.com/wlynxg/anet"
	"tailscale.com/net/netmon"
)

// Go's net.Interfaces() and net.Interface.Addrs() open a netlink socket and
// call bind() on it explicitly; Android's SELinux policy denies that bind
// operation on a netlink_route_socket to every app in the untrusted_app
// domain. tailcat.Client.initLocked calls netmon.New() unconditionally
// before it can dial anything, so with no working interface getter that
// call fails outright with "netmon.New: route ip+net: netlinkrib:
// permission denied" -- the exact error PROBE_SSH_FAIL reported once this
// repo started dialing Tailcat addresses this way.
//
// Before the in-process tailcat.Client added in this branch, every Tailcat
// SSH connection went through the separate tailcat subprocess, and
// cmd/tailcat/netmon_android.go (added by
// patches/tailcat/android-netmon-interface-getter.patch) already registered
// this same workaround there -- so netmon.New() never ran unpatched inside
// an Android process. Forwarding's tailcatClientDialer and agent.connect's
// direct-address path now call netmon.New() in *this* binary instead, and
// that patch only touches the tailcat module, not meowshell's, so the
// meowshell binary needs its own copy of the registration or every direct
// Tailcat connection on Android regresses back to the permission denial.
//
// anet reimplements the same netlink RIB queries the stdlib does, but never
// binds the socket explicitly -- it lets the kernel's implicit
// autobind-on-send handle that instead, which Android's policy does not
// deny -- so it returns real, non-empty interface data where the stdlib
// call fails outright.
func init() {
	netmon.RegisterInterfaceGetter(func() ([]netmon.Interface, error) {
		ifs, err := anet.Interfaces()
		if err != nil {
			return nil, err
		}
		ret := make([]netmon.Interface, len(ifs))
		for i := range ifs {
			// AltAddrs, not a second RegisterInterfaceGetter-style hook:
			// netmon.Interface.Addrs() only consults i.Interface.Addrs()
			// (the same netlink-based stdlib call) when AltAddrs is nil,
			// so leaving it unset here would hit the identical permission
			// denial one level down, per interface, right after fixing the
			// enumeration itself.
			addrs, _ := anet.InterfaceAddrsByInterface(&ifs[i])
			ret[i] = netmon.Interface{Interface: &ifs[i], AltAddrs: addrs}
		}
		return ret, nil
	})
}
