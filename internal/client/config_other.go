//go:build !unix

package client

import "os"

// On systems without Unix ownership and modes (Windows), the configuration
// relies on the ACLs of the user's profile directory: Go reports ordinary
// files as mode 0666 there, so mode checks would reject every file.

func checkConfigFile(string, os.FileInfo) error { return nil }

func checkConfigPath(string) error { return nil }
