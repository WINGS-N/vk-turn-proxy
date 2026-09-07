//go:build windows

package main

func enableTUIInputMode() func() {
	return nil
}

func isInteractiveStdin() bool {
	return false
}
