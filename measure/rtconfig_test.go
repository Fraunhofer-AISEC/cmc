// Copyright (c) 2021 Fraunhofer AISEC
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

package measure

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestGetConfigMeasurement(t *testing.T) {
	type args struct {
		id         string
		configData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "Measure Config Success",
			args: args{
				id:         "mycontainer",
				configData: configData,
			},
			want:    []byte{0x17, 0x76, 0xdf, 0xed, 0x31, 0x7c, 0xa1, 0x03, 0xd1, 0x49, 0x13, 0xd6, 0x5e, 0x86, 0x2e, 0x8a, 0xa8, 0x0a, 0x3c, 0x73, 0x87, 0xeb, 0x3f, 0x36, 0x20, 0xd3, 0xe3, 0x2d, 0x46, 0x4c, 0x54, 0x62},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, _, err := GetConfigMeasurement(tt.args.id, tt.args.configData)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetConfigMeasurement() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetConfigMeasurement() = %v, want %v", hex.EncodeToString(got), hex.EncodeToString(tt.want))
			}
		})
	}
}

func Test_normalize(t *testing.T) {
	type args struct {
		id         string
		configData []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "normalize_Success",
			args: args{
				id:         "8d6f55b059bca4d130b60e29807c5a5f63014b8673ad7cee69b7fb84b03b6443",
				configData: dockerConfig,
			},
			want:    normalizedDockerConfig,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := normalize(tt.args.id, tt.args.configData)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalize() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("\nGOT = %v,\nWANT= %v", string(got), string(tt.want))
			}
		})
	}
}

var (
	normalizedDockerConfig = []byte(`{"hooks":{"prestart":[{"args":["libnetwork-setkey","-exec-root=/var/run/docker","<container-id>","<docker-network-controller-id>"],"path":"/usr/bin/dockerd"}]},"hostname":"<container-id>","linux":{"cgroupsPath":"system.slice:docker:<container-id>","maskedPaths":["/proc/asound","/sys/devices/virtual/powercap"],"namespaces":[{"type":"mount"}],"readonlyPaths":["/proc/bus","/proc/sysrq-trigger"],"resources":{"blockIO":{},"devices":[{"access":"rwm","allow":false}]},"seccomp":{"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X32"],"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"syscalls":[{"action":"SCMP_ACT_ALLOW","names":["chroot"]}]},"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"}},"mounts":[{"destination":"/etc/resolv.conf","options":["rbind","rprivate"],"source":"/var/lib/docker/containers/<container-id>/resolv.conf","type":"bind"}],"ociVersion":"1.2.0","process":{"args":["/bin/sh"],"capabilities":{"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE"]},"cwd":"/","env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","HOSTNAME=<container-id>","TERM=xterm"],"user":{"gid":0,"uid":0}}}`)

	dockerConfig = []byte(`
{
  "ociVersion": "1.2.0",
  "process": {
    "terminal": true,
    "consoleSize": {
      "height": 31,
      "width": 127
    },
    "user": {
	  "gid": 0,
      "uid": 0
    },
    "args": [
      "/bin/sh"
    ],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "HOSTNAME=8d6f55b059bc",
      "TERM=xterm"
    ],
    "cwd": "/",
    "capabilities": {
      "permitted": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE"
      ]
    }
  },
  "root": {
    "path": "/var/lib/docker/overlay2/985be77ec6cff5fdb13520443dd9a67e9e9e4d2a70d189009d7dda3e7458b9c1/merged"
  },
  "hostname": "8d6f55b059bc",
  "mounts": [
    {
      "destination": "/etc/resolv.conf",
      "type": "bind",
      "source": "/var/lib/docker/containers/8d6f55b059bca4d130b60e29807c5a5f63014b8673ad7cee69b7fb84b03b6443/resolv.conf",
      "options": [
        "rbind",
        "rprivate"
      ]
    }
  ],
  "hooks": {
    "prestart": [
      {
        "path": "/usr/bin/dockerd",
        "args": [
          "libnetwork-setkey",
          "-exec-root=/var/run/docker",
          "8d6f55b059bca4d130b60e29807c5a5f63014b8673ad7cee69b7fb84b03b6443",
          "99b3e86f39be"
        ]
      }
    ]
  },
  "linux": {
    "sysctl": {
      "net.ipv4.ip_unprivileged_port_start": "0",
      "net.ipv4.ping_group_range": "0 2147483647"
    },
    "resources": {
      "devices": [
        {
          "allow": false,
          "access": "rwm"
        }
      ],
      "blockIO": {}
    },
    "cgroupsPath": "system.slice:docker:8d6f55b059bca4d130b60e29807c5a5f63014b8673ad7cee69b7fb84b03b6443",
    "namespaces": [
      {
        "type": "mount"
      }
    ],
    "seccomp": {
      "defaultAction": "SCMP_ACT_ERRNO",
      "defaultErrnoRet": 1,
      "architectures": [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X32"
      ],
      "syscalls": [
        {
          "names": [
            "chroot"
          ],
          "action": "SCMP_ACT_ALLOW"
        }
      ]
    },
    "maskedPaths": [
      "/proc/asound",
      "/sys/devices/virtual/powercap"
    ],
    "readonlyPaths": [
      "/proc/bus",
      "/proc/sysrq-trigger"
    ]
  }
}
`)

	configData = []byte{
		0x7b, 0x0a, 0x20, 0x20, 0x22, 0x6f, 0x63, 0x69, 0x56, 0x65, 0x72, 0x73,
		0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x31, 0x2e, 0x30, 0x2e, 0x32,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x22, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73,
		0x73, 0x22, 0x3a, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74,
		0x65, 0x72, 0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x22, 0x3a, 0x20, 0x74, 0x72,
		0x75, 0x65, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x75, 0x73, 0x65,
		0x72, 0x22, 0x3a, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x75, 0x69, 0x64, 0x22, 0x3a, 0x20, 0x30, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x67, 0x69, 0x64, 0x22, 0x3a, 0x20, 0x30,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x61, 0x72, 0x67, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x70, 0x65,
		0x62, 0x62, 0x6c, 0x65, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x22, 0x65, 0x6e, 0x74, 0x65, 0x72, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x2d, 0x2d, 0x76, 0x65, 0x72, 0x62, 0x6f,
		0x73, 0x65, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x5d, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x22, 0x65, 0x6e, 0x76, 0x22, 0x3a, 0x20, 0x5b, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x50, 0x41, 0x54, 0x48, 0x3d,
		0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2f, 0x73,
		0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x6f, 0x63,
		0x61, 0x6c, 0x2f, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f,
		0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69,
		0x6e, 0x3a, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x62, 0x69, 0x6e,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x54, 0x45,
		0x52, 0x4d, 0x3d, 0x78, 0x74, 0x65, 0x72, 0x6d, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x48, 0x4f, 0x4d, 0x45, 0x3d, 0x2f,
		0x72, 0x6f, 0x6f, 0x74, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x5d, 0x2c,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x63, 0x77, 0x64, 0x22, 0x3a, 0x20,
		0x22, 0x2f, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x63, 0x61,
		0x70, 0x61, 0x62, 0x69, 0x6c, 0x69, 0x74, 0x69, 0x65, 0x73, 0x22, 0x3a,
		0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x62, 0x6f,
		0x75, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50, 0x5f,
		0x41, 0x55, 0x44, 0x49, 0x54, 0x5f, 0x57, 0x52, 0x49, 0x54, 0x45, 0x22,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43,
		0x41, 0x50, 0x5f, 0x4b, 0x49, 0x4c, 0x4c, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50, 0x5f, 0x4e,
		0x45, 0x54, 0x5f, 0x42, 0x49, 0x4e, 0x44, 0x5f, 0x53, 0x45, 0x52, 0x56,
		0x49, 0x43, 0x45, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5d,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x65, 0x66, 0x66,
		0x65, 0x63, 0x74, 0x69, 0x76, 0x65, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50, 0x5f,
		0x41, 0x55, 0x44, 0x49, 0x54, 0x5f, 0x57, 0x52, 0x49, 0x54, 0x45, 0x22,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43,
		0x41, 0x50, 0x5f, 0x4b, 0x49, 0x4c, 0x4c, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50, 0x5f, 0x4e,
		0x45, 0x54, 0x5f, 0x42, 0x49, 0x4e, 0x44, 0x5f, 0x53, 0x45, 0x52, 0x56,
		0x49, 0x43, 0x45, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5d,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x69, 0x6e, 0x68,
		0x65, 0x72, 0x69, 0x74, 0x61, 0x62, 0x6c, 0x65, 0x22, 0x3a, 0x20, 0x5b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41,
		0x50, 0x5f, 0x41, 0x55, 0x44, 0x49, 0x54, 0x5f, 0x57, 0x52, 0x49, 0x54,
		0x45, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x43, 0x41, 0x50, 0x5f, 0x4b, 0x49, 0x4c, 0x4c, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50,
		0x5f, 0x4e, 0x45, 0x54, 0x5f, 0x42, 0x49, 0x4e, 0x44, 0x5f, 0x53, 0x45,
		0x52, 0x56, 0x49, 0x43, 0x45, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x5d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x70,
		0x65, 0x72, 0x6d, 0x69, 0x74, 0x74, 0x65, 0x64, 0x22, 0x3a, 0x20, 0x5b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41,
		0x50, 0x5f, 0x41, 0x55, 0x44, 0x49, 0x54, 0x5f, 0x57, 0x52, 0x49, 0x54,
		0x45, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x43, 0x41, 0x50, 0x5f, 0x4b, 0x49, 0x4c, 0x4c, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50,
		0x5f, 0x4e, 0x45, 0x54, 0x5f, 0x42, 0x49, 0x4e, 0x44, 0x5f, 0x53, 0x45,
		0x52, 0x56, 0x49, 0x43, 0x45, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x5d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x61,
		0x6d, 0x62, 0x69, 0x65, 0x6e, 0x74, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50, 0x5f,
		0x41, 0x55, 0x44, 0x49, 0x54, 0x5f, 0x57, 0x52, 0x49, 0x54, 0x45, 0x22,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43,
		0x41, 0x50, 0x5f, 0x4b, 0x49, 0x4c, 0x4c, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x43, 0x41, 0x50, 0x5f, 0x4e,
		0x45, 0x54, 0x5f, 0x42, 0x49, 0x4e, 0x44, 0x5f, 0x53, 0x45, 0x52, 0x56,
		0x49, 0x43, 0x45, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5d,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x72, 0x6c, 0x69, 0x6d, 0x69, 0x74, 0x73, 0x22, 0x3a, 0x20, 0x5b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a,
		0x20, 0x22, 0x52, 0x4c, 0x49, 0x4d, 0x49, 0x54, 0x5f, 0x4e, 0x4f, 0x46,
		0x49, 0x4c, 0x45, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x22, 0x68, 0x61, 0x72, 0x64, 0x22, 0x3a, 0x20, 0x31, 0x30,
		0x32, 0x34, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x73, 0x6f, 0x66, 0x74, 0x22, 0x3a, 0x20, 0x31, 0x30, 0x32, 0x34,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x5d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x4e,
		0x65, 0x77, 0x50, 0x72, 0x69, 0x76, 0x69, 0x6c, 0x65, 0x67, 0x65, 0x73,
		0x22, 0x3a, 0x20, 0x74, 0x72, 0x75, 0x65, 0x0a, 0x20, 0x20, 0x7d, 0x2c,
		0x0a, 0x20, 0x20, 0x22, 0x72, 0x6f, 0x6f, 0x74, 0x22, 0x3a, 0x20, 0x7b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x70, 0x61, 0x74, 0x68, 0x22, 0x3a,
		0x20, 0x22, 0x72, 0x6f, 0x6f, 0x74, 0x66, 0x73, 0x22, 0x0a, 0x20, 0x20,
		0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x22, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61,
		0x6d, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x75, 0x6d, 0x6f, 0x63, 0x69, 0x2d,
		0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x22, 0x6d, 0x6f, 0x75, 0x6e, 0x74, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e,
		0x22, 0x3a, 0x20, 0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22,
		0x3a, 0x20, 0x22, 0x70, 0x72, 0x6f, 0x63, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22,
		0x3a, 0x20, 0x22, 0x70, 0x72, 0x6f, 0x63, 0x22, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61,
		0x74, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x2f, 0x64, 0x65, 0x76,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79,
		0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x74, 0x6d, 0x70, 0x66, 0x73, 0x22,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x6f, 0x75,
		0x72, 0x63, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x74, 0x6d, 0x70, 0x66, 0x73,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f, 0x70,
		0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x73, 0x75, 0x69,
		0x64, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x61, 0x74, 0x69, 0x6d, 0x65,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x6d, 0x6f, 0x64, 0x65, 0x3d, 0x37, 0x35, 0x35, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x69, 0x7a, 0x65,
		0x3d, 0x36, 0x35, 0x35, 0x33, 0x36, 0x6b, 0x22, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x5d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e,
		0x22, 0x3a, 0x20, 0x22, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x70, 0x74, 0x73,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79,
		0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x64, 0x65, 0x76, 0x70, 0x74, 0x73,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x6f,
		0x75, 0x72, 0x63, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x64, 0x65, 0x76, 0x70,
		0x74, 0x73, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x73,
		0x75, 0x69, 0x64, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x22, 0x6e, 0x6f, 0x65, 0x78, 0x65, 0x63, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x65, 0x77,
		0x69, 0x6e, 0x73, 0x74, 0x61, 0x6e, 0x63, 0x65, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x70, 0x74, 0x6d, 0x78,
		0x6d, 0x6f, 0x64, 0x65, 0x3d, 0x30, 0x36, 0x36, 0x36, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6d, 0x6f, 0x64,
		0x65, 0x3d, 0x30, 0x36, 0x32, 0x30, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x5d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22,
		0x3a, 0x20, 0x22, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x6d, 0x22,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70,
		0x65, 0x22, 0x3a, 0x20, 0x22, 0x74, 0x6d, 0x70, 0x66, 0x73, 0x22, 0x2c,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x6f, 0x75, 0x72,
		0x63, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x73, 0x68, 0x6d, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f, 0x70, 0x74, 0x69, 0x6f,
		0x6e, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x73, 0x75, 0x69, 0x64, 0x22, 0x2c,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f,
		0x65, 0x78, 0x65, 0x63, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x64, 0x65, 0x76, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6d, 0x6f, 0x64,
		0x65, 0x3d, 0x31, 0x37, 0x37, 0x37, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x69, 0x7a, 0x65, 0x3d, 0x36,
		0x35, 0x35, 0x33, 0x36, 0x6b, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x5d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x64,
		0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x3a,
		0x20, 0x22, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x6d, 0x71, 0x75, 0x65, 0x75,
		0x65, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74,
		0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x6d, 0x71, 0x75, 0x65, 0x75,
		0x65, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73,
		0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x6d, 0x71, 0x75,
		0x65, 0x75, 0x65, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x3a, 0x20, 0x5b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f,
		0x73, 0x75, 0x69, 0x64, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x65, 0x78, 0x65, 0x63, 0x22, 0x2c,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f,
		0x64, 0x65, 0x76, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5d,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x64, 0x65, 0x73,
		0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x20, 0x22,
		0x2f, 0x73, 0x79, 0x73, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x62, 0x69,
		0x6e, 0x64, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x2f, 0x73,
		0x79, 0x73, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x72, 0x62, 0x69,
		0x6e, 0x64, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x22, 0x6e, 0x6f, 0x73, 0x75, 0x69, 0x64, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x65, 0x78,
		0x65, 0x63, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x22, 0x6e, 0x6f, 0x64, 0x65, 0x76, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x72, 0x6f, 0x22, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x5d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x22, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69,
		0x6f, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x72,
		0x65, 0x73, 0x6f, 0x6c, 0x76, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x22, 0x2c,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65,
		0x22, 0x3a, 0x20, 0x22, 0x62, 0x69, 0x6e, 0x64, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
		0x22, 0x3a, 0x20, 0x22, 0x2f, 0x65, 0x74, 0x63, 0x2f, 0x72, 0x65, 0x73,
		0x6f, 0x6c, 0x76, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e,
		0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x22, 0x6e, 0x6f, 0x73, 0x75, 0x69, 0x64, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6e, 0x6f, 0x64,
		0x65, 0x76, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x22, 0x6e, 0x6f, 0x65, 0x78, 0x65, 0x63, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x72, 0x62, 0x69, 0x6e,
		0x64, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x72, 0x6f, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x5d,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x0a, 0x20, 0x20, 0x5d, 0x2c, 0x0a,
		0x20, 0x20, 0x22, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f,
		0x6e, 0x73, 0x22, 0x3a, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x6f, 0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x74,
		0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67, 0x65,
		0x2e, 0x61, 0x72, 0x63, 0x68, 0x69, 0x74, 0x65, 0x63, 0x74, 0x75, 0x72,
		0x65, 0x22, 0x3a, 0x20, 0x22, 0x61, 0x6d, 0x64, 0x36, 0x34, 0x22, 0x2c,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f, 0x72, 0x67, 0x2e, 0x6f, 0x70,
		0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73,
		0x2e, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e, 0x61, 0x75, 0x74, 0x68, 0x6f,
		0x72, 0x22, 0x3a, 0x20, 0x22, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x6f, 0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e,
		0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67,
		0x65, 0x2e, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x64, 0x69, 0x67, 0x65, 0x73,
		0x74, 0x22, 0x3a, 0x20, 0x22, 0x63, 0x36, 0x38, 0x37, 0x31, 0x61, 0x65,
		0x38, 0x62, 0x35, 0x34, 0x66, 0x62, 0x33, 0x65, 0x64, 0x30, 0x62, 0x61,
		0x34, 0x64, 0x66, 0x34, 0x65, 0x62, 0x39, 0x38, 0x35, 0x32, 0x37, 0x65,
		0x39, 0x61, 0x36, 0x36, 0x39, 0x32, 0x30, 0x38, 0x38, 0x66, 0x65, 0x30,
		0x63, 0x32, 0x66, 0x32, 0x32, 0x36, 0x30, 0x61, 0x39, 0x33, 0x33, 0x34,
		0x38, 0x35, 0x33, 0x30, 0x39, 0x32, 0x62, 0x34, 0x37, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x6f, 0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65,
		0x6e, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e,
		0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
		0x64, 0x22, 0x3a, 0x20, 0x22, 0x32, 0x30, 0x32, 0x33, 0x2d, 0x31, 0x30,
		0x2d, 0x30, 0x35, 0x54, 0x30, 0x37, 0x3a, 0x33, 0x33, 0x3a, 0x33, 0x32,
		0x2e, 0x39, 0x30, 0x32, 0x30, 0x33, 0x36, 0x35, 0x35, 0x34, 0x5a, 0x22,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f, 0x72, 0x67, 0x2e, 0x6f,
		0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
		0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e, 0x65, 0x78, 0x70, 0x6f,
		0x73, 0x65, 0x64, 0x50, 0x6f, 0x72, 0x74, 0x73, 0x22, 0x3a, 0x20, 0x22,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f, 0x72, 0x67, 0x2e,
		0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65,
		0x72, 0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e, 0x6c, 0x69, 0x63,
		0x65, 0x6e, 0x73, 0x65, 0x73, 0x22, 0x3a, 0x20, 0x22, 0x41, 0x70, 0x61,
		0x63, 0x68, 0x65, 0x2d, 0x32, 0x2e, 0x30, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x22, 0x6f, 0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63,
		0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6d,
		0x61, 0x67, 0x65, 0x2e, 0x6f, 0x73, 0x22, 0x3a, 0x20, 0x22, 0x6c, 0x69,
		0x6e, 0x75, 0x78, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f,
		0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x74, 0x61,
		0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e,
		0x72, 0x65, 0x66, 0x2e, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x3a, 0x20, 0x22,
		0x6e, 0x67, 0x69, 0x6e, 0x78, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x6f, 0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e,
		0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67,
		0x65, 0x2e, 0x73, 0x74, 0x6f, 0x70, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x6c,
		0x22, 0x3a, 0x20, 0x22, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x6f, 0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x74,
		0x61, 0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67, 0x65,
		0x2e, 0x74, 0x69, 0x74, 0x6c, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x6e, 0x67,
		0x69, 0x6e, 0x78, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x6f,
		0x72, 0x67, 0x2e, 0x6f, 0x70, 0x65, 0x6e, 0x63, 0x6f, 0x6e, 0x74, 0x61,
		0x69, 0x6e, 0x65, 0x72, 0x73, 0x2e, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x2e,
		0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x22, 0x3a, 0x20, 0x22, 0x31,
		0x2e, 0x32, 0x33, 0x2e, 0x33, 0x22, 0x0a, 0x20, 0x20, 0x7d, 0x2c, 0x0a,
		0x20, 0x20, 0x22, 0x6c, 0x69, 0x6e, 0x75, 0x78, 0x22, 0x3a, 0x20, 0x7b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x75, 0x69, 0x64, 0x4d, 0x61, 0x70,
		0x70, 0x69, 0x6e, 0x67, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72,
		0x49, 0x44, 0x22, 0x3a, 0x20, 0x30, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x68, 0x6f, 0x73, 0x74, 0x49, 0x44, 0x22,
		0x3a, 0x20, 0x31, 0x30, 0x30, 0x30, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x69, 0x7a, 0x65, 0x22, 0x3a, 0x20,
		0x31, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x5d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22, 0x67, 0x69,
		0x64, 0x4d, 0x61, 0x70, 0x70, 0x69, 0x6e, 0x67, 0x73, 0x22, 0x3a, 0x20,
		0x5b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x63, 0x6f, 0x6e, 0x74, 0x61,
		0x69, 0x6e, 0x65, 0x72, 0x49, 0x44, 0x22, 0x3a, 0x20, 0x30, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x68, 0x6f, 0x73,
		0x74, 0x49, 0x44, 0x22, 0x3a, 0x20, 0x31, 0x30, 0x30, 0x30, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x73, 0x69, 0x7a,
		0x65, 0x22, 0x3a, 0x20, 0x31, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x7d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x5d, 0x2c, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x22, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x73,
		0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79,
		0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x63, 0x67, 0x72, 0x6f, 0x75, 0x70,
		0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22,
		0x70, 0x69, 0x64, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7d,
		0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22,
		0x3a, 0x20, 0x22, 0x69, 0x70, 0x63, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7b,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79,
		0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x75, 0x74, 0x73, 0x22, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a, 0x20, 0x22, 0x6d, 0x6f, 0x75,
		0x6e, 0x74, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x2c,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x74, 0x79, 0x70, 0x65, 0x22, 0x3a,
		0x20, 0x22, 0x75, 0x73, 0x65, 0x72, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x7d, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x5d, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x22, 0x6d, 0x61, 0x73, 0x6b, 0x65, 0x64, 0x50, 0x61,
		0x74, 0x68, 0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x6b, 0x63, 0x6f,
		0x72, 0x65, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63,
		0x79, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x22, 0x2c, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x74,
		0x69, 0x6d, 0x65, 0x72, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63,
		0x2f, 0x74, 0x69, 0x6d, 0x65, 0x72, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73,
		0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x2f, 0x70,
		0x72, 0x6f, 0x63, 0x2f, 0x73, 0x63, 0x68, 0x65, 0x64, 0x5f, 0x64, 0x65,
		0x62, 0x75, 0x67, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x2f, 0x73, 0x79, 0x73, 0x2f, 0x66, 0x69, 0x72, 0x6d, 0x77, 0x61,
		0x72, 0x65, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x63, 0x73, 0x69, 0x22, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x5d, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x72, 0x65, 0x61, 0x64, 0x6f, 0x6e, 0x6c, 0x79, 0x50, 0x61, 0x74, 0x68,
		0x73, 0x22, 0x3a, 0x20, 0x5b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x61, 0x73, 0x6f, 0x75, 0x6e,
		0x64, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x2f,
		0x70, 0x72, 0x6f, 0x63, 0x2f, 0x62, 0x75, 0x73, 0x22, 0x2c, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f,
		0x66, 0x73, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22,
		0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x69, 0x72, 0x71, 0x22, 0x2c, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63,
		0x2f, 0x73, 0x79, 0x73, 0x22, 0x2c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x22, 0x2f, 0x70, 0x72, 0x6f, 0x63, 0x2f, 0x73, 0x79, 0x73, 0x72,
		0x71, 0x2d, 0x74, 0x72, 0x69, 0x67, 0x67, 0x65, 0x72, 0x22, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x5d, 0x0a, 0x20, 0x20, 0x7d, 0x0a, 0x7d, 0x0a,
	}
)
