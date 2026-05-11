// Copyright (c) 2024 - 2026 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package convert

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/v2/pkg/archive"
	mobySeccomp "github.com/moby/profiles/seccomp"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/runtime-spec/specs-go"

	mobyoci "github.com/moby/moby/v2/daemon/pkg/oci"

	"github.com/Fraunhofer-AISEC/cmc/measure"
)

// fakeContainerID is a fixed 64-char hex placeholder used to stand in for the
// real container ID. measure.Normalize() will replace it with <container-id>.
const fakeContainerID = "3d6772b4f84ed47595d72a2c4c5ffd15f5bb72c7507fe26f2aaee2c69d5633ba"

// shmDefaultSize is Docker's default shared-memory size (64 MiB).
const shmDefaultSize = int64(64 * 1024 * 1024)

// mountPoints is the list of docker mount points for
// bind-mounting things into a container
var mountPoints = map[string]string{
	"/dev/pts":         "dir",
	"/dev/shm":         "dir",
	"/proc":            "dir",
	"/sys":             "dir",
	"/.dockerenv":      "file",
	"/etc/resolv.conf": "file",
	"/etc/hosts":       "file",
	"/etc/hostname":    "file",
	"/dev/console":     "file",
	"/etc/mtab":        "/proc/mounts",
}

// ConvertOpts holds options that cannot be derived and thus must be configured
type ConvertOpts struct {
	// AppArmor enables the docker-default AppArmor profile
	AppArmor bool
	// CPUs is the number of CPUs on the target host, used to generate
	// thermal_throttle masked paths (0 means no thermal_throttle paths)
	CPUs int
	// AdditionalGIDs are supplementary group IDs for the container process
	AdditionalGIDs []uint32
}

type parsedImage struct {
	config *ocispec.Image
	layers []string
}

// Convert unpacks the input OCI image tar into an OCI runtime bundle
func Convert(inputFile, outputDir string, opts ConvertOpts) error {
	img, err := parseOciImageTar(inputFile)
	if err != nil {
		return fmt.Errorf("parse OCI image: %w", err)
	}

	rootfsDir := filepath.Join(outputDir, "rootfs")
	if err := os.MkdirAll(rootfsDir, 0755); err != nil {
		return fmt.Errorf("create rootfs dir: %w", err)
	}

	if err := extractRootfs(inputFile, img.layers, rootfsDir); err != nil {
		return fmt.Errorf("extract rootfs: %w", err)
	}

	if err := setupInitLayer(rootfsDir); err != nil {
		return fmt.Errorf("setup init layer: %w", err)
	}

	spec, err := generateSpec(img.config, opts)
	if err != nil {
		return fmt.Errorf("generate spec: %w", err)
	}

	rawConfig, err := json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("marshal spec: %w", err)
	}

	_, normalizedConfig, err := measure.GetSpecMeasurement(fakeContainerID, rawConfig)
	if err != nil {
		return fmt.Errorf("normalize spec: %w", err)
	}

	if err := os.WriteFile(filepath.Join(outputDir, "config.json"), normalizedConfig, 0644); err != nil {
		return fmt.Errorf("write config.json: %w", err)
	}

	log.Infof("Written OCI runtime bundle to %s", outputDir)
	return nil
}

// parseOciImageTar reads the OCI image layout from the tar archive and returns
// the image config along with the ordered layer blob digests
func parseOciImageTar(tarPath string) (*parsedImage, error) {
	blobs, err := readTarBlobs(tarPath)
	if err != nil {
		return nil, err
	}

	indexData, ok := blobs["index.json"]
	if !ok {
		return nil, fmt.Errorf("index.json not found in OCI image tar")
	}

	index := new(ocispec.Index)
	if err := json.Unmarshal(indexData, index); err != nil {
		return nil, fmt.Errorf("parse index.json: %w", err)
	}
	if len(index.Manifests) == 0 {
		return nil, fmt.Errorf("no manifests in OCI index")
	}

	manifestDigest := digestToPath(index.Manifests[0].Digest.String())
	manifestData, ok := blobs[manifestDigest]
	if !ok {
		return nil, fmt.Errorf("manifest blob %s not found", manifestDigest)
	}

	manifest := new(ocispec.Manifest)
	if err := json.Unmarshal(manifestData, manifest); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	configDigest := digestToPath(manifest.Config.Digest.String())
	configData, ok := blobs[configDigest]
	if !ok {
		return nil, fmt.Errorf("config blob %s not found", configDigest)
	}

	imgConfig := new(ocispec.Image)
	if err := json.Unmarshal(configData, imgConfig); err != nil {
		return nil, fmt.Errorf("parse image config: %w", err)
	}

	var layerDigests []string
	for _, l := range manifest.Layers {
		layerDigests = append(layerDigests, digestToPath(l.Digest.String()))
	}

	return &parsedImage{config: imgConfig, layers: layerDigests}, nil
}

// readTarBlobs reads all entries from the tar into a map keyed by archive path.
func readTarBlobs(tarPath string) (map[string][]byte, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, fmt.Errorf("open tar: %w", err)
	}
	defer f.Close()

	blobs := make(map[string][]byte)
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read tar: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read blob %s: %w", hdr.Name, err)
			}
			blobs[hdr.Name] = data
		}
	}
	return blobs, nil
}

// digestToPath converts "sha256:<hex>" to "blobs/sha256/<hex>".
func digestToPath(digest string) string {
	parts := strings.SplitN(digest, ":", 2)
	if len(parts) == 2 {
		return filepath.Join("blobs", parts[0], parts[1])
	}
	return digest
}

// extractRootfs applies the image layers in order to rootfsDir, producing the
// merged container filesystem.
func extractRootfs(tarPath string, layerDigests []string, rootfsDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("open tar: %w", err)
	}
	defer f.Close()

	type entry struct {
		offset int64
		size   int64
	}
	layerOffsets := make(map[string]entry)
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}
		for _, ld := range layerDigests {
			if hdr.Name == ld || strings.TrimPrefix(hdr.Name, "./") == ld {
				offset, _ := f.Seek(0, io.SeekCurrent)
				layerOffsets[ld] = entry{offset: offset, size: hdr.Size}
			}
		}
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return fmt.Errorf("skip entry: %w", err)
		}
	}

	for _, ld := range layerDigests {
		e, ok := layerOffsets[ld]
		if !ok {
			return fmt.Errorf("layer blob %s not found in tar", ld)
		}
		if _, err := f.Seek(e.offset, io.SeekStart); err != nil {
			return fmt.Errorf("seek to layer: %w", err)
		}
		lr := io.LimitReader(f, e.size)
		if err := applyLayer(lr, rootfsDir); err != nil {
			return fmt.Errorf("apply layer %s: %w", ld, err)
		}
	}
	return nil
}

// applyLayer decompresses a gzipped tar layer and applies it to rootfsDir
// using containerd's archive.Apply
func applyLayer(r io.Reader, rootfsDir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gz.Close()

	_, err = archive.Apply(context.Background(), rootfsDir, gz)
	return err
}

// setupInitLayer creates the docker mount-point stubs in the rootfs
func setupInitLayer(rootfsDir string) error {
	for p, t := range mountPoints {
		parts := strings.Split(p, "/")
		prev := "/"
		for _, p := range parts[1:] {
			prev = filepath.Join(prev, p)
			os.Remove(filepath.Join(rootfsDir, prev))
		}

		full := filepath.Join(rootfsDir, p)
		if _, err := os.Stat(full); err == nil {
			continue
		}
		if err := os.MkdirAll(filepath.Join(rootfsDir, filepath.Dir(p)), 0755); err != nil {
			return err
		}
		switch t {
		case "dir":
			if err := os.MkdirAll(full, 0755); err != nil {
				return err
			}
		case "file":
			f, err := os.OpenFile(full, os.O_CREATE, 0755)
			if err != nil {
				return err
			}
			f.Close()
		default:
			if err := os.Symlink(t, full); err != nil {
				return err
			}
		}
	}
	return nil
}

// generateSpec builds an OCI runtime spec that tries to match the spec, which
// is generated when invoking `docker run <container>`.
//
// Starting from the moby DefaultLinuxSpec() we apply the container configuration
// following the moby behaviour:
//
//   - withCommonOptions: hostname, sysctl, HOSTNAME env, process args/env/cwd
//   - withCgroups      : cgroupsPath
//   - WithDevices      : double the device cgroup rules
//   - WithNamespaces   : add cgroup namespace
//   - withMounts       : /dev/shm size, Docker bind mounts
//   - WithAppArmor     : apparmor profile
//   - WithSeccomp      : default seccomp profile
//
// The spec uses fakeContainerID wherever the real container ID would appear.
// measure.Normalize() later replaces it with a placeholder.
func generateSpec(imgCfg *ocispec.Image, opts ConvertOpts) (*specs.Spec, error) {

	// Start with the default spec from moby
	s := mobyoci.DefaultLinuxSpec()

	// DefaultLinuxSpec reads the build host sysfs to determine CPU
	// thermal_throttle masked paths. We replace this with deterministic paths
	// based on the configured CPU count, as we cannot assume anything about the
	// host the container is running on
	s.Linux.MaskedPaths = deterministicMaskedPaths(s.Linux.MaskedPaths, opts.CPUs)

	s.Hostname = fakeContainerID

	// Default network sysctls Docker sets for containers with a private
	// network namespace
	s.Linux.Sysctl = map[string]string{
		"net.ipv4.ping_group_range":           "0 2147483647",
		"net.ipv4.ip_unprivileged_port_start": "0",
	}

	// Default process
	s.Process.User = specs.User{
		UID:            0,
		GID:            0,
		AdditionalGids: opts.AdditionalGIDs,
	}

	s.Process.Args = append(imgCfg.Config.Entrypoint, imgCfg.Config.Cmd...)

	// Docker prepends HOSTNAME=<id> then appends the image's env vars.
	env := []string{"HOSTNAME=" + fakeContainerID}
	env = append(env, imgCfg.Config.Env...)
	s.Process.Env = env

	cwd := imgCfg.Config.WorkingDir
	if cwd == "" {
		cwd = "/"
	}
	s.Process.Cwd = cwd

	oomAdj := 0
	s.Process.OOMScoreAdj = &oomAdj

	// Just use "rootfs", will be replaced by measure.Normalize()
	s.Root = &specs.Root{Path: "rootfs"}

	// Default cgroups path
	s.Linux.CgroupsPath = fmt.Sprintf("system.slice:docker:%s", fakeContainerID)

	// Docker copies s.Linux.Resources.Devices then appends the copy back,
	// resulting in the base entry list being doubled
	s.Linux.Resources.Devices = append(s.Linux.Resources.Devices, s.Linux.Resources.Devices...)

	// Docker adds the cgroup namespace when the container has a private cgroup namespace
	s.Linux.Namespaces = append(s.Linux.Namespaces, specs.LinuxNamespace{
		Type: specs.CgroupNamespace,
	})

	// Docker withMounts appends the SHM size from HostConfig.ShmSize to the
	// /dev/shm options (default 64 MiB).
	shmSizeOpt := fmt.Sprintf("size=%d", shmDefaultSize)
	for i := range s.Mounts {
		if s.Mounts[i].Destination == "/dev/shm" {
			s.Mounts[i].Options = append(s.Mounts[i].Options, shmSizeOpt)
			break
		}
	}

	// Docker adds bind mounts for the container-specific hostname, hosts,
	// and resolv.conf from the Docker data root. We have to set the paths
	// here directly, as we cannot call moby's NetworkMounts()
	ctrDir := filepath.Join("/var/lib/docker", "containers", fakeContainerID)
	networkMountOpts := []string{"rbind", "rprivate"}
	s.Mounts = append(s.Mounts,
		specs.Mount{Destination: "/etc/hostname", Type: "bind", Source: ctrDir + "/hostname", Options: networkMountOpts},
		specs.Mount{Destination: "/etc/hosts", Type: "bind", Source: ctrDir + "/hosts", Options: networkMountOpts},
		specs.Mount{Destination: "/etc/resolv.conf", Type: "bind", Source: ctrDir + "/resolv.conf", Options: networkMountOpts},
	)

	// Default empty BlockIO block.
	s.Linux.Resources.BlockIO = &specs.LinuxBlockIO{}

	// Docker sets the AppArmor profile when the host supports it. For
	// precomputation, the user must configure this
	if opts.AppArmor {
		s.Process.ApparmorProfile = "docker-default"
	}

	// Precompute the moby withSeccomp behaviour without relying on the host
	seccomp, err := hostIndependentSeccomp(&s)
	if err != nil {
		return nil, fmt.Errorf("get default seccomp profile: %w", err)
	}
	s.Linux.Seccomp = seccomp

	return &s, nil
}

// deterministicMaskedPaths takes the masked paths returned by
// mobyoci.DefaultLinuxSpec() (which may contain host-dependent
// thermal_throttle entries), strips them, and adds back deterministic
// entries for the configured number of target CPUs.
func deterministicMaskedPaths(fromUpstream []string, cpus int) []string {
	var paths []string
	for _, p := range fromUpstream {
		if strings.HasPrefix(p, "/sys/devices/system/cpu/cpu") &&
			strings.HasSuffix(p, "/thermal_throttle") {
			continue
		}
		paths = append(paths, p)
	}
	for i := range cpus {
		paths = append(paths, fmt.Sprintf("/sys/devices/system/cpu/cpu%d/thermal_throttle", i))
	}
	return paths
}

// hostIndependentSeccomp generates the default Docker seccomp profile
// without depending on the build host's kernel version.
// mobySeccomp.GetDefaultProfile() calls unix.Uname() to check the host
// kernel and conditionally includes syscalls based on MinKernel filters.
// Instead, we strip all MinKernel filters and process the profile via
// LoadProfile, simply assuming a modern kernel (>= 4.8).
func hostIndependentSeccomp(s *specs.Spec) (*specs.LinuxSeccomp, error) {
	profile := mobySeccomp.DefaultProfile()

	for _, sc := range profile.Syscalls {
		if sc.Includes != nil {
			sc.Includes.MinKernel = nil
		}
		if sc.Excludes != nil {
			sc.Excludes.MinKernel = nil
		}
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("marshal seccomp profile: %w", err)
	}

	return mobySeccomp.LoadProfile(string(data), s)
}
