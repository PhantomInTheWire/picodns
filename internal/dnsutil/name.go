// Package dnsutil provides helper functions for DNS name manipulation and extraction.
package dnsutil

import (
	"strings"
)

// NormalizeName returns a normalized domain name (lowercase, no trailing dot).
func NormalizeName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// JoinLabels joins a slice of domain name labels with dots.
// Returns "." if the labels slice is empty.
func JoinLabels(labels []string) string {
	if len(labels) == 0 {
		return "."
	}
	return strings.Join(labels, ".")
}

// SplitLabels splits a domain name into its constituent labels.
// Returns an empty slice for empty names or root (".") names.
func SplitLabels(name string) []string {
	if name == "" || name == "." {
		return nil
	}
	name = strings.TrimSuffix(name, ".")

	// Count dots to pre-allocate slice
	dotCount := strings.Count(name, ".")
	labels := make([]string, 0, dotCount+1)

	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			if i > start {
				labels = append(labels, name[start:i])
			}
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

// IsSubdomain checks if child is a subdomain of parent.
// Both names should be normalized (lowercase, no trailing dot).
func IsSubdomain(child, parent string) bool {
	if parent == "." {
		return true
	}
	child = strings.ToLower(strings.TrimSuffix(child, "."))
	parent = strings.ToLower(strings.TrimSuffix(parent, "."))

	if child == parent {
		return true
	}

	return strings.HasSuffix(child, "."+parent)
}
