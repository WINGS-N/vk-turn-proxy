//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package main

func enableTUIInputMode() func() {
	return nil
}

func isInteractiveStdin() bool {
	return false
}
