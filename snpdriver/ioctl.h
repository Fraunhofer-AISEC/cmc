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

#pragma once

struct snp_report_req {
	uint8_t user_data[64];
	uint32_t vmpl;
	uint8_t rsvd[28];
};

struct snp_report_resp {
	uint8_t data[4000];
};

struct snp_guest_req_ioctl {
	uint8_t msg_version;
	uint64_t req_data;
	uint64_t resp_data;
	uint64_t fw_err;
};

#define SNP_GUEST_REQ_IOC_TYPE	'S'

#define SNP_GET_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x0, struct snp_guest_req_ioctl)
#define SNP_GET_DERIVED_KEY _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x1, struct snp_guest_req_ioctl)
#define SNP_GET_EXT_REPORT _IOWR(SNP_GUEST_REQ_IOC_TYPE, 0x2, struct snp_guest_req_ioctl)

int
snp_dump_ar(uint8_t *buf, size_t size, uint8_t *user_data, size_t user_data_size);