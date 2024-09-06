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

#include "snp.h"

int
snp_dump_cert(uint8_t *buf, size_t size)
{
	struct snp_guest_req_ioctl data;
	struct snp_ext_report_req req;
	struct snp_report_resp resp;
	struct snp_cert_table cert_table;
	uint8_t *certs = NULL;
	size_t page_size = 0;
	size_t nr_pages = 0;
	int ret = -1;
	int fd = -1;

	memset(&data, 0, sizeof(data));
	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	memset(&cert_table, 0, sizeof(cert_table));

	// Set to invalid address
	req.certs_address = (uint64_t) -1;

	data.msg_version = 1;
	data.req_data = (uint64_t) &req;
	data.resp_data = (uint64_t) &resp;

	errno = 0;
	fd = open("/dev/sev-guest", O_RDWR);

	// First just query the size of the stored certificates
	ret = ioctl(fd, SNP_GET_EXT_REPORT, &data);
	if (ret == -1 && data.fw_err != 0x100000000) {
		fprintf(stderr, "snp-ar: ioctl SNP_GET_EXT_REPORT on /dev/sev-guest returned %d\n\n", ret);
		fprintf(stderr, "errno:             %d (%s)\n", errno, strerror(errno));
		fprintf(stderr, "fw_err:            0x%lx\n\n", data.fw_err);
		goto out;
	}

	if (req.certs_len == 0) {
		fprintf(stderr, "No certificates stored\n");
		ret = -1;
		goto out;
	}

	// Allocate memory in full pages for certificates
	page_size = sysconf(_SC_PAGESIZE);
	nr_pages = req.certs_len / page_size;
	if (req.certs_len % page_size != 0) {
		nr_pages++;
	}
	cert_table.entry = calloc(page_size, nr_pages);
	if (!cert_table.entry) {
		ret = -1;
		fprintf(stderr, "failed to allocate memory\n");
		goto out;
	}

	req.certs_address = (uint64_t)cert_table.entry;

	// Now get extended report with enough memory for certificates
	ret = ioctl(fd, SNP_GET_EXT_REPORT, &data);
	if (ret == -1) {
		fprintf(stderr, "snp-ar: ioctl SNP_GET_EXT_REPORT on /dev/sev-guest returned %d\n\n", ret);
		fprintf(stderr, "errno:             %d (%s)\n", errno, strerror(errno));
		fprintf(stderr, "fw_err:            0x%lx\n\n", data.fw_err);
		goto out;
	}

	if (size < req.certs_len) {
		fprintf(stderr, "buffer not large enough to store VLEK (%ld, must be %d)\n", size, req.certs_len);
		ret = -1;
		goto out;
	}

	// Dump only certificate
	certs = (uint8_t *)cert_table.entry;
	memcpy(buf, certs + cert_table.entry->offset, cert_table.entry->length);

	ret = 0;

out:
	close(fd);

	return ret;
}
