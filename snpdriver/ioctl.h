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