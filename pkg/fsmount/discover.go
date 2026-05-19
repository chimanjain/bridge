package fsmount

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

const procSelfMountinfo = "/proc/self/mountinfo"

// DiscoverSecretMounts returns the mount points of webhook-injected
// secret/token projected volumes visible to the current process, read from
// /proc/self/mountinfo.
//
// It returns every tmpfs mount whose mount point starts with /run/secrets/
// or /var/run/secrets/ — the canonical paths used by the kubelet auto-mount,
// EKS Pod Identity, Azure Workload Identity, and similar webhooks. These
// mounts are added at pod-admission time and are not present in the
// Deployment's PodSpec, so callers that derive --mount-roots from the spec
// miss them entirely.
//
// /var/run is a symlink to /run on most distros, so the kernel records the
// canonical /run/secrets/... form even when the workload spec uses
// /var/run/secrets/.... For each discovered mount, both forms are returned so
// authorize() prefix-matches whichever form a client uses.
func DiscoverSecretMounts() ([]string, error) {
	f, err := os.Open(procSelfMountinfo)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", procSelfMountinfo, err)
	}
	defer f.Close()

	var paths []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		mp, ok := parseSecretMountLine(scanner.Text())
		if !ok {
			continue
		}
		paths = append(paths, mp)
		if alias, ok := strings.CutPrefix(mp, "/run/"); ok {
			paths = append(paths, "/var/run/"+alias)
		} else if alias, ok := strings.CutPrefix(mp, "/var/run/"); ok {
			paths = append(paths, "/run/"+alias)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", procSelfMountinfo, err)
	}
	return paths, nil
}

// parseSecretMountLine extracts the mount point from one /proc/self/mountinfo
// line if it represents a tmpfs mount under /run/secrets/ or
// /var/run/secrets/. Returns ("", false) for any other line.
//
// mountinfo format (one line per mount):
//
//	<mount id> <parent id> <maj:min> <root> <mount point> <opts> [<optional>...] - <fs type> <source> <super opts>
//
// The fixed fields are space-separated up to a literal " - " separator; after
// the separator the filesystem type is the first token. See
// https://www.kernel.org/doc/Documentation/filesystems/proc.txt section 3.5.
func parseSecretMountLine(line string) (string, bool) {
	const sep = " - "
	sepIdx := strings.Index(line, sep)
	if sepIdx < 0 {
		return "", false
	}
	head := strings.Fields(line[:sepIdx])
	tail := strings.Fields(line[sepIdx+len(sep):])
	if len(head) < 5 || len(tail) < 1 {
		return "", false
	}
	mountPoint, fsType := head[4], tail[0]
	if fsType != "tmpfs" {
		return "", false
	}
	if !strings.HasPrefix(mountPoint, "/run/secrets/") &&
		!strings.HasPrefix(mountPoint, "/var/run/secrets/") {
		return "", false
	}
	return mountPoint, true
}
