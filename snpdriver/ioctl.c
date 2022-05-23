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

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/ioctl.h>

#include "ioctl.h"

#define __packed __attribute__ ((__packed__))

int
snp_dump_ar(uint8_t *buf, size_t size, uint8_t *user_data, size_t user_data_size)
{
	struct snp_guest_req_ioctl data;
	struct snp_report_req req;
	struct snp_report_resp resp;
	int ret = -1;
	int fd = -1;

	if (size < 4000) {
		return -1;
	}
	if (user_data_size > sizeof(req.user_data)) {
		return -1;
	}

	memset(&data, 0, sizeof(data));
	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	memcpy(req.user_data, user_data, user_data_size);

	data.msg_version = 1;
	data.req_data = (uint64_t) &req;
	data.resp_data = (uint64_t) &resp;

	errno = 0;
	fd = open("/dev/sev-guest", O_RDWR);
	ret = ioctl(fd, SNP_GET_REPORT, &data);

	if (ret != 0) {
		fprintf(stderr, "snp-ar: ioctl SNP_GET_REPORT on /dev/sev-guest returned %d\n\n", ret);
		fprintf(stderr, "errno:             %d (%s)\n", errno, strerror(errno));
		fprintf(stderr, "fw_err:            0x%lx\n\n", data.fw_err);
	}

	memcpy(buf, resp.data, sizeof(resp.data));

	close(fd);

	return ret;
}
