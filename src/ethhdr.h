#pragma once

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	EthHdr() {}
	EthHdr(u_char *data) {
		dmac_ = Mac((uint8_t *)data);
		data += 6;
		smac_ = Mac((uint8_t *)data);
		data += 6;
		type_ = *((uint16_t *)data);
	}

	Mac dmac() { return dmac_; }
	Mac smac() { return smac_; }
	uint16_t type() { return ntohs(type_); }

	// Type(type_)
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};

	bool isNull() {
		return (dmac_.isNull() || smac_.isNull());
	}
};
typedef EthHdr *PEthHdr;
#pragma pack(pop)
