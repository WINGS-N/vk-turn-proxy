//go:build !windows

package main

// pinConnToPhysical is a no-op off Windows. The tunnel bypass for vkturn's underlay is
// handled by the host data plane there (SO_MARK + cgroup on Linux); only Windows needs
// the per-socket IP_UNICAST_IF pin.
func pinConnToPhysical(conn any) {}
