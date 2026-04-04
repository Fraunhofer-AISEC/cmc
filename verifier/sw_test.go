// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

package verifier

import (
	"encoding/json"
	"testing"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

func TestVerifySw(t *testing.T) {
	type args struct {
		evidence   ar.Evidence
		collateral ar.Collateral
		nonce      []byte
		refvals    []ar.Component
	}
	tests := []struct {
		name  string
		args  args
		want  ar.Status
		want1 bool
	}{
		{
			name: "Valid SW Measurement",
			args: args{
				evidence: ar.Evidence{
					Type: ar.TYPE_EVIDENCE_SW,
					Data: validSwEvidence,
				},
				collateral: ar.Collateral{
					Artifacts: validSwArtifacts,
					Key:       validSwKey,
				},
				nonce:   validSwNonce,
				refvals: []ar.Component{validUbuntuRefVal},
			},
			want:  ar.StatusSuccess,
			want1: true,
		},
		{
			name: "Invalid Key",
			args: args{
				evidence: ar.Evidence{
					Type: ar.TYPE_EVIDENCE_SW,
					Data: validSwEvidence,
				},
				collateral: ar.Collateral{
					Artifacts: validSwArtifacts,
					Key:       invalidSwKey,
				},
				nonce:   validSwNonce,
				refvals: []ar.Component{validUbuntuRefVal},
			},
			want:  ar.StatusFail,
			want1: false,
		},
		{
			name: "Invalid Nonce",
			args: args{
				evidence: ar.Evidence{
					Type: ar.TYPE_EVIDENCE_SW,
					Data: validSwEvidence,
				},
				collateral: ar.Collateral{
					Artifacts: validSwArtifacts,
					Key:       validSwKey,
				},
				nonce:   invalidSwNonce,
				refvals: []ar.Component{validUbuntuRefVal},
			},
			want:  ar.StatusFail,
			want1: false,
		},
		{
			name: "Invalid Artifacts",
			args: args{
				evidence: ar.Evidence{
					Type: ar.TYPE_EVIDENCE_SW,
					Data: validSwEvidence,
				},
				collateral: ar.Collateral{
					Artifacts: invalidSwArtifacts,
					Key:       validSwKey,
				},
				nonce:   validSwNonce,
				refvals: []ar.Component{validUbuntuRefVal},
			},
			want:  ar.StatusFail,
			want1: false,
		},
		{
			name: "Invalid Evidence",
			args: args{
				evidence: ar.Evidence{
					Type: ar.TYPE_EVIDENCE_SW,
					Data: invalidSwEvidence,
				},
				collateral: ar.Collateral{
					Artifacts: validSwArtifacts,
					Key:       validSwKey,
				},
				nonce:   validSwNonce,
				refvals: []ar.Component{validUbuntuRefVal},
			},
			want:  ar.StatusFail,
			want1: false,
		},
		{
			name: "Invalid Refval",
			args: args{
				evidence: ar.Evidence{
					Type: ar.TYPE_EVIDENCE_SW,
					Data: validSwEvidence,
				},
				collateral: ar.Collateral{
					Artifacts: validSwArtifacts,
					Key:       validSwKey,
				},
				nonce:   validSwNonce,
				refvals: []ar.Component{invalidSwRefVal},
			},
			want:  ar.StatusFail,
			want1: false,
		},
		{
			name: "Invalid OCI Config",
			args: args{
				evidence: ar.Evidence{
					Type: ar.TYPE_EVIDENCE_SW,
					Data: validSwEvidence,
				},
				collateral: ar.Collateral{
					Artifacts: validSwArtifacts,
					Key:       validSwKey,
				},
				nonce:   validSwNonce,
				refvals: []ar.Component{invalidSwRefValOciConfig},
			},
			want:  ar.StatusFail,
			want1: false,
		},
	}
	logrus.SetLevel(logrus.TraceLevel)

	for _, tt := range tests {

		t.Run(tt.name, func(t *testing.T) {
			got, got1 := VerifySw(
				tt.args.evidence,
				tt.args.collateral,
				tt.args.nonce,
				tt.args.refvals)
			if got.Summary.Status != tt.want {
				t.Errorf("VerifySw() got = %v, want %v", got.Summary.Status, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("VerifySw() got = %v, want %v", got1, tt.want)
			}
		})
		// End FUT
	}
}

var (
	validSwArtifacts = []ar.Artifact{
		{
			Type: ar.TYPE_SW_EVENTLOG,
			Events: []ar.Component{
				{
					Hashes: []ar.ReferenceHash{{
						Alg:     "SHA-256",
						Content: dec("e8db6f822ecf7d968db4ae1ce9242f0e50ddf605e74d7fbdfc93a8bb641f3093")},
					},
					Name: "359e464721925b79c836b8a7997b5645d9b3a6b46998b7377ebec72cb971b94b",
					CtrData: &ar.CtrData{
						ConfigSha256: dec("c7ae16b284d164c0036e1f1cb437b906cfc3e8296b712b38df468fda350866ac"),
						RootfsSha256: dec("b3efcaa760118501b34effbb07d099d774ecf7ee0bddf6233c7e8bc958c16d1e"),
						OciSpec:      validUbuntuOciConfig,
					},
				},
			},
		},
	}

	invalidSwArtifacts = []ar.Artifact{
		{
			Type: ar.TYPE_SW_EVENTLOG,
			Events: []ar.Component{
				{
					Hashes: []ar.ReferenceHash{{
						Alg:     "SHA-256",
						Content: dec("6dc7a115a4c4a4f02b49cb0866d8f63f33e86cbf933238276411a8f26961e9ff")},
					},
					Name: "07f475b29a92233363d27544683b5ea04f54ca514d742ab5a0b41bdb5914d4b",
					CtrData: &ar.CtrData{
						ConfigSha256: dec("333c809d8ed04b01af781b964dd05fc888aea04732edcaff9d940757d2e48be8"),
						RootfsSha256: dec("44563228698774cb66bf3fe1432ab3c8ea1adfffd9d6d388bc40d73a68cb533c"),
						OciSpec:      validUbuntuOciConfig,
					},
				},
			},
		},
	}

	validUbuntuRefVal = ar.Component{
		Type: ar.TYPE_REFVAL_SW,
		Name: "OCI Runtime Bundle Rootfs Digest: 359e464721925b79c836b8a7997b5645d9b3a6b46998b7377ebec72cb971b94b",
		Hashes: []ar.ReferenceHash{{
			Alg:     "SHA-256",
			Content: dec("b3efcaa760118501b34effbb07d099d774ecf7ee0bddf6233c7e8bc958c16d1e")},
		},
		CtrData: &ar.CtrData{
			OciSpec: validUbuntuOciConfig,
		},
		Optional: true,
	}

	invalidSwRefVal = ar.Component{
		Type: ar.TYPE_REFVAL_SW,
		Name: "OCI Runtime Bundle Digest",
		Hashes: []ar.ReferenceHash{{
			Alg:     "SHA-256",
			Content: dec("ff5ed62e8fb85decea88ffee33274245d2924e2e961b3cc95be6e09a6ae5a25d")},
		},
		CtrData: &ar.CtrData{
			OciSpec: validUbuntuOciConfig,
		},
		Optional: true,
	}

	invalidSwRefValOciConfig = ar.Component{
		Type: ar.TYPE_REFVAL_SW,
		Name: "OCI Runtime Bundle Rootfs Digest: 359e464721925b79c836b8a7997b5645d9b3a6b46998b7377ebec72cb971b94b",
		Hashes: []ar.ReferenceHash{{
			Alg:     "SHA-256",
			Content: dec("b3efcaa760118501b34effbb07d099d774ecf7ee0bddf6233c7e8bc958c16d1e")},
		},
		CtrData: &ar.CtrData{
			OciSpec: invalidUbuntuOciConfig,
		},
		Optional: true,
	}

	validSwNonce = dec("8962e5c8e9522190551a3c4f40cf886e798d5ff1d698bc951fc11781cdb5f63a")

	invalidSwNonce = dec("ff021a63554e0e58")

	validSwKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1FR9E9hGARR5zXum61IOsk0Nxu2m
vtg74ppZCbzteTDGQZyFx+xwABoCTWbYdB/zihjZqob4+sWZpSUPFRF99A==
-----END PUBLIC KEY-----`)

	invalidSwKey = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsLIpIWx9YzPSeqBvAXxhxqe5eXzR
NROq1l1GJwBCCEpS1DzJu4twnCG5fXIdwSAytyBi4PwbrlzMR1L/XnM9kQ==
-----END PUBLIC KEY-----`)

	validSwEvidence = []byte(`{"payload":"eyJub25jZSI6ImlXTGx5T2xTSVpCVkdqeFBRTStJYm5tTlgvSFdtTHlWSDhFWGdjMjE5am89Iiwic2hhMjU2IjoiN0xsQ3VzYzluSjJmQzZSWFBVNTZhYTM0Y2dUVnVURzFqck9QaWtqaFN0cz0ifQ","protected":"eyJhbGciOiJFUzI1NiJ9","signature":"2mQ_l5j5pxscBmkvh6AZ4uVv9RArO5zT0pntaybmH8LdJAmS2Px3v3yrASPpCBpZPmg92lEOthsb1qLHPyU5zg"}`)

	invalidSwEvidence = []byte(`{"payload":"eyJub25jZSI6ImlXTGx5T2xTSVpCVkdqeFBRTStJYm5tTlgvSFdtTHlWSDhFWGdjMjE5am89Iiwic2hhMjU2IjoiN0xsQ3VzYzluSjJmQzZSWFBVNTZhYTM0Y2dUVnVURzFqck9ZZZZZZZZZZZZZZZZ","protected":"eyJhbGciOiJFUzI1NiJ9","signature":"2mQ_l5j5pxscBmkvh6AZ4uVv9RArO5zT0pntaybmH8LdJAmS2Px3v3yrASPpCBpZPmg92lEOthsb1qLHPyU5zg"}`)

	validUbuntuOciConfig = unmarshalSpec([]byte(`{"ociVersion":"1.2.1","process":{"user":{"uid":0,"gid":0,"additionalGids":[0]},"args":["/bin/bash"],"env":["HOSTNAME=\u003ccontainer-id\u003e","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"cwd":"/","capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"apparmorProfile":"docker-default","oomScoreAdj":0},"hostname":"\u003ccontainer-id\u003e","mounts":[{"destination":"/etc/hostname","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hostname","options":["rbind","rprivate"]},{"destination":"/etc/hosts","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hosts","options":["rbind","rprivate"]},{"destination":"/etc/resolv.conf","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/resolv.conf","options":["rbind","rprivate"]},{"destination":"/sys/fs/cgroup","type":"cgroup","source":"cgroup","options":["ro","nosuid","noexec","nodev"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"]},{"destination":"/dev/mqueue","type":"mqueue","source":"mqueue","options":["nosuid","noexec","nodev"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","noexec","nodev","mode=1777","size=67108864"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]}],"linux":{"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"},"resources":{"devices":[{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"},{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"}],"blockIO":{}},"cgroupsPath":"system.slice:docker:\u003ccontainer-id\u003e","namespaces":[{"type":"mount"},{"type":"network"},{"type":"uts"},{"type":"pid"},{"type":"ipc"},{"type":"cgroup"}],"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["accept","accept4","access","adjtimex","alarm","bind","brk","cachestat","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchmodat2","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_requeue","futex_time64","futex_wait","futex_waitv","futex_wake","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","getxattrat","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","ipc","kill","landlock_add_rule","landlock_create_ruleset","landlock_restrict_self","lchown","lchown32","lgetxattr","link","linkat","listen","listmount","listxattr","listxattrat","llistxattr","_llseek","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","map_shadow_stack","membarrier","memfd_create","memfd_secret","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","mseal","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","name_to_handle_at","nanosleep","newfstatat","_newselect","open","openat","openat2","pause","pidfd_open","pidfd_send_signal","pipe","pipe2","pkey_alloc","pkey_free","pkey_mprotect","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","process_mrelease","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","removexattrat","rename","renameat","renameat2","restart_syscall","riscv_hwprobe","rmdir","rseq","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","setxattrat","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statmount","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","uretprobe","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"],"action":"SCMP_ACT_ALLOW"},{"names":["process_vm_readv","process_vm_writev","ptrace"],"action":"SCMP_ACT_ALLOW"},{"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":40,"op":"SCMP_CMP_NE"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":0,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":8,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131072,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131080,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":4294967295,"op":"SCMP_CMP_EQ"}]},{"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW"},{"names":["modify_ldt"],"action":"SCMP_ACT_ALLOW"},{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},{"names":["chroot"],"action":"SCMP_ACT_ALLOW"}]},"maskedPaths":["/proc/acpi","/proc/asound","/proc/interrupts","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/sched_debug","/proc/scsi","/proc/timer_list","/proc/timer_stats","/sys/devices/virtual/powercap","/sys/firmware","/sys/devices/system/cpu/cpu0/thermal_throttle","/sys/devices/system/cpu/cpu1/thermal_throttle","/sys/devices/system/cpu/cpu2/thermal_throttle","/sys/devices/system/cpu/cpu3/thermal_throttle","/sys/devices/system/cpu/cpu4/thermal_throttle","/sys/devices/system/cpu/cpu5/thermal_throttle","/sys/devices/system/cpu/cpu6/thermal_throttle","/sys/devices/system/cpu/cpu7/thermal_throttle"],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]}}`))

	invalidUbuntuOciConfig = unmarshalSpec([]byte(`{"ociVersion":"1.1.0","process":{"user":{"uid":0,"gid":0,"additionalGids":[0]},"args":["/bin/bash"],"env":["HOSTNAME=\u003ccontainer-id\u003e","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"cwd":"/","capabilities":{"bounding":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"effective":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"],"permitted":["CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_FSETID","CAP_FOWNER","CAP_MKNOD","CAP_NET_RAW","CAP_SETGID","CAP_SETUID","CAP_SETFCAP","CAP_SETPCAP","CAP_NET_BIND_SERVICE","CAP_SYS_CHROOT","CAP_KILL","CAP_AUDIT_WRITE"]},"apparmorProfile":"docker-default","oomScoreAdj":0},"hostname":"\u003ccontainer-id\u003e","mounts":[{"destination":"/etc/hostname","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hostname","options":["rbind","rprivate"]},{"destination":"/etc/hosts","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/hosts","options":["rbind","rprivate"]},{"destination":"/etc/resolv.conf","type":"bind","source":"/var/lib/docker/containers/\u003ccontainer-id\u003e/resolv.conf","options":["rbind","rprivate"]},{"destination":"/sys/fs/cgroup","type":"cgroup","source":"cgroup","options":["ro","nosuid","noexec","nodev"]},{"destination":"/dev/pts","type":"devpts","source":"devpts","options":["nosuid","noexec","newinstance","ptmxmode=0666","mode=0620","gid=5"]},{"destination":"/dev/mqueue","type":"mqueue","source":"mqueue","options":["nosuid","noexec","nodev"]},{"destination":"/proc","type":"proc","source":"proc","options":["nosuid","noexec","nodev"]},{"destination":"/dev/shm","type":"tmpfs","source":"shm","options":["nosuid","noexec","nodev","mode=1777","size=67108864"]},{"destination":"/sys","type":"sysfs","source":"sysfs","options":["nosuid","noexec","nodev","ro"]},{"destination":"/dev","type":"tmpfs","source":"tmpfs","options":["nosuid","strictatime","mode=755","size=65536k"]}],"linux":{"sysctl":{"net.ipv4.ip_unprivileged_port_start":"0","net.ipv4.ping_group_range":"0 2147483647"},"resources":{"devices":[{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"},{"allow":false,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":5,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":3,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":9,"access":"rwm"},{"allow":true,"type":"c","major":1,"minor":8,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":0,"access":"rwm"},{"allow":true,"type":"c","major":5,"minor":1,"access":"rwm"},{"allow":false,"type":"c","major":10,"minor":229,"access":"rwm"}],"blockIO":{}},"cgroupsPath":"system.slice:docker:\u003ccontainer-id\u003e","namespaces":[{"type":"mount"},{"type":"network"},{"type":"uts"},{"type":"pid"},{"type":"ipc"},{"type":"cgroup"}],"seccomp":{"defaultAction":"SCMP_ACT_ERRNO","defaultErrnoRet":1,"architectures":["SCMP_ARCH_X86_64","SCMP_ARCH_X86","SCMP_ARCH_X32"],"syscalls":[{"names":["accept","accept4","access","adjtimex","alarm","bind","brk","cachestat","capget","capset","chdir","chmod","chown","chown32","clock_adjtime","clock_adjtime64","clock_getres","clock_getres_time64","clock_gettime","clock_gettime64","clock_nanosleep","clock_nanosleep_time64","close","close_range","connect","copy_file_range","creat","dup","dup2","dup3","epoll_create","epoll_create1","epoll_ctl","epoll_ctl_old","epoll_pwait","epoll_pwait2","epoll_wait","epoll_wait_old","eventfd","eventfd2","execve","execveat","exit","exit_group","faccessat","faccessat2","fadvise64","fadvise64_64","fallocate","fanotify_mark","fchdir","fchmod","fchmodat","fchmodat2","fchown","fchown32","fchownat","fcntl","fcntl64","fdatasync","fgetxattr","flistxattr","flock","fork","fremovexattr","fsetxattr","fstat","fstat64","fstatat64","fstatfs","fstatfs64","fsync","ftruncate","ftruncate64","futex","futex_requeue","futex_time64","futex_wait","futex_waitv","futex_wake","futimesat","getcpu","getcwd","getdents","getdents64","getegid","getegid32","geteuid","geteuid32","getgid","getgid32","getgroups","getgroups32","getitimer","getpeername","getpgid","getpgrp","getpid","getppid","getpriority","getrandom","getresgid","getresgid32","getresuid","getresuid32","getrlimit","get_robust_list","getrusage","getsid","getsockname","getsockopt","get_thread_area","gettid","gettimeofday","getuid","getuid32","getxattr","getxattrat","inotify_add_watch","inotify_init","inotify_init1","inotify_rm_watch","io_cancel","ioctl","io_destroy","io_getevents","io_pgetevents","io_pgetevents_time64","ioprio_get","ioprio_set","io_setup","io_submit","ipc","kill","landlock_add_rule","landlock_create_ruleset","landlock_restrict_self","lchown","lchown32","lgetxattr","link","linkat","listen","listmount","listxattr","listxattrat","llistxattr","_llseek","lremovexattr","lseek","lsetxattr","lstat","lstat64","madvise","map_shadow_stack","membarrier","memfd_create","memfd_secret","mincore","mkdir","mkdirat","mknod","mknodat","mlock","mlock2","mlockall","mmap","mmap2","mprotect","mq_getsetattr","mq_notify","mq_open","mq_timedreceive","mq_timedreceive_time64","mq_timedsend","mq_timedsend_time64","mq_unlink","mremap","mseal","msgctl","msgget","msgrcv","msgsnd","msync","munlock","munlockall","munmap","name_to_handle_at","nanosleep","newfstatat","_newselect","open","openat","openat2","pause","pidfd_open","pidfd_send_signal","pipe","pipe2","pkey_alloc","pkey_free","pkey_mprotect","poll","ppoll","ppoll_time64","prctl","pread64","preadv","preadv2","prlimit64","process_mrelease","pselect6","pselect6_time64","pwrite64","pwritev","pwritev2","read","readahead","readlink","readlinkat","readv","recv","recvfrom","recvmmsg","recvmmsg_time64","recvmsg","remap_file_pages","removexattr","removexattrat","rename","renameat","renameat2","restart_syscall","riscv_hwprobe","rmdir","rseq","rt_sigaction","rt_sigpending","rt_sigprocmask","rt_sigqueueinfo","rt_sigreturn","rt_sigsuspend","rt_sigtimedwait","rt_sigtimedwait_time64","rt_tgsigqueueinfo","sched_getaffinity","sched_getattr","sched_getparam","sched_get_priority_max","sched_get_priority_min","sched_getscheduler","sched_rr_get_interval","sched_rr_get_interval_time64","sched_setaffinity","sched_setattr","sched_setparam","sched_setscheduler","sched_yield","seccomp","select","semctl","semget","semop","semtimedop","semtimedop_time64","send","sendfile","sendfile64","sendmmsg","sendmsg","sendto","setfsgid","setfsgid32","setfsuid","setfsuid32","setgid","setgid32","setgroups","setgroups32","setitimer","setpgid","setpriority","setregid","setregid32","setresgid","setresgid32","setresuid","setresuid32","setreuid","setreuid32","setrlimit","set_robust_list","setsid","setsockopt","set_thread_area","set_tid_address","setuid","setuid32","setxattr","setxattrat","shmat","shmctl","shmdt","shmget","shutdown","sigaltstack","signalfd","signalfd4","sigprocmask","sigreturn","socketcall","socketpair","splice","stat","stat64","statfs","statfs64","statmount","statx","symlink","symlinkat","sync","sync_file_range","syncfs","sysinfo","tee","tgkill","time","timer_create","timer_delete","timer_getoverrun","timer_gettime","timer_gettime64","timer_settime","timer_settime64","timerfd_create","timerfd_gettime","timerfd_gettime64","timerfd_settime","timerfd_settime64","times","tkill","truncate","truncate64","ugetrlimit","umask","uname","unlink","unlinkat","uretprobe","utime","utimensat","utimensat_time64","utimes","vfork","vmsplice","wait4","waitid","waitpid","write","writev"],"action":"SCMP_ACT_ALLOW"},{"names":["process_vm_readv","process_vm_writev","ptrace"],"action":"SCMP_ACT_ALLOW"},{"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":40,"op":"SCMP_CMP_NE"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":0,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":8,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131072,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":131080,"op":"SCMP_CMP_EQ"}]},{"names":["personality"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":4294967295,"op":"SCMP_CMP_EQ"}]},{"names":["arch_prctl"],"action":"SCMP_ACT_ALLOW"},{"names":["modify_ldt"],"action":"SCMP_ACT_ALLOW"},{"names":["clone"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":2114060288,"op":"SCMP_CMP_MASKED_EQ"}]},{"names":["clone3"],"action":"SCMP_ACT_ERRNO","errnoRet":38},{"names":["chroot"],"action":"SCMP_ACT_ALLOW"}]},"maskedPaths":["/proc/acpi","/proc/asound","/proc/interrupts","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/sched_debug","/proc/scsi","/proc/timer_list","/proc/timer_stats","/sys/devices/virtual/powercap","/sys/firmware","/sys/devices/system/cpu/cpu0/thermal_throttle","/sys/devices/system/cpu/cpu1/thermal_throttle","/sys/devices/system/cpu/cpu2/thermal_throttle","/sys/devices/system/cpu/cpu3/thermal_throttle","/sys/devices/system/cpu/cpu4/thermal_throttle","/sys/devices/system/cpu/cpu5/thermal_throttle","/sys/devices/system/cpu/cpu6/thermal_throttle","/sys/devices/system/cpu/cpu7/thermal_throttle"],"readonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"]}}`))
)

func unmarshalSpec(raw []byte) *specs.Spec {
	spec := new(specs.Spec)
	err := json.Unmarshal(raw, spec)
	if err != nil {
		log.Errorf("generate test vectors: failed to unmarshal spec: %v", err)
	}
	return spec
}
