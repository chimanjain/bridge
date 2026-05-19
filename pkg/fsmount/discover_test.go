package fsmount

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseSecretMountLine(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
		ok   bool
	}{
		{
			name: "eks pod identity token",
			line: "2381 2334 0:272 / /run/secrets/eks.amazonaws.com/serviceaccount ro,relatime - tmpfs tmpfs rw,size=61656332k",
			want: "/run/secrets/eks.amazonaws.com/serviceaccount",
			ok:   true,
		},
		{
			name: "kubelet service-account auto-mount",
			line: "2380 2334 0:273 / /run/secrets/kubernetes.io/serviceaccount ro,relatime - tmpfs tmpfs rw,size=61656332k",
			want: "/run/secrets/kubernetes.io/serviceaccount",
			ok:   true,
		},
		{
			name: "azure workload identity token",
			line: "2377 2334 0:271 / /run/secrets/azure/tokens ro,relatime - tmpfs tmpfs rw,size=61656332k",
			want: "/run/secrets/azure/tokens",
			ok:   true,
		},
		{
			name: "var/run alias form (some distros don't symlink /var/run to /run)",
			line: "100 1 0:99 / /var/run/secrets/eks.amazonaws.com/serviceaccount ro,relatime - tmpfs tmpfs rw",
			want: "/var/run/secrets/eks.amazonaws.com/serviceaccount",
			ok:   true,
		},
		{
			name: "rejects non-tmpfs mount under same prefix",
			line: "100 1 259:1 / /run/secrets/something rw - xfs /dev/nvme0n1p1 rw",
			ok:   false,
		},
		{
			name: "rejects tmpfs mount outside /run/secrets",
			line: "100 1 0:99 / /etc/bridge/tls ro,relatime - tmpfs tmpfs rw",
			ok:   false,
		},
		{
			name: "rejects malformed line (no separator)",
			line: "100 1 0:99 / /run/secrets/x ro,relatime tmpfs tmpfs rw",
			ok:   false,
		},
		{
			name: "handles optional fields before separator",
			line: "2381 2334 0:272 / /run/secrets/eks.amazonaws.com/serviceaccount ro,relatime master:1 - tmpfs tmpfs rw,size=61656332k",
			want: "/run/secrets/eks.amazonaws.com/serviceaccount",
			ok:   true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSecretMountLine(tc.line)
			assert.Equal(t, tc.ok, ok)
			if tc.ok {
				assert.Equal(t, tc.want, got)
			}
		})
	}
}
