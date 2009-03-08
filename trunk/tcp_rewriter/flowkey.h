#ifndef _FLOW_KEY_H_
#define _FLOW_KEY_H_

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <cstring>

#define FLOW_KEY_LEN 14

class TcpFlowKey
{
public:
	uint8_t data[FLOW_KEY_LEN];
	const unsigned len;

	struct FlowKey
	{
		uint32_t srcIp;
		uint32_t dstIp;
		uint16_t srcPort;
		uint16_t dstPort;
	};

	TcpFlowKey() : len(FLOW_KEY_LEN)
	{
		memset(data,0,sizeof(data));
	}

	void reverse(const TcpFlowKey& flow)
	{
		getFlowKey()->srcIp = flow.getFlowKey()->dstIp;
		getFlowKey()->dstIp = flow.getFlowKey()->srcIp;
		getFlowKey()->srcPort = flow.getFlowKey()->dstPort;
		getFlowKey()->dstPort = flow.getFlowKey()->srcPort;
	}

	TcpFlowKey(const uint8_t* packet_data, bool reverseOrder = false, uint8_t ip_offset = 14) 
		: len(FLOW_KEY_LEN), is_tcp(false)
	{
		memset(data,0, sizeof(data));
		uint32_t ip1, ip2;
		uint16_t port1, port2;
		struct ip* iph = (struct ip*)(packet_data + ip_offset);
		// TODO: Handle fragments!!!!
		// TODO: handle ipv6
		if (iph->ip_p != IPPROTO_TCP || iph->ip_v != 4) {
			return;
		}
		is_tcp = true;
		struct tcphdr* tcph = (struct tcphdr*)(iph + (iph->ip_hl >> 2));
		if (!reverseOrder) {
			getFlowKey()->srcIp = *(uint32_t*)&iph->ip_src;
			getFlowKey()->dstIp = *(uint32_t*)&iph->ip_dst;
			getFlowKey()->srcPort = tcph->th_sport;
			getFlowKey()->dstPort = tcph->th_dport;
		} else {
			getFlowKey()->srcIp = *(uint32_t*)&iph->ip_dst;
			getFlowKey()->dstIp = *(uint32_t*)&iph->ip_src;
			getFlowKey()->srcPort = tcph->th_dport;
			getFlowKey()->dstPort = tcph->th_sport;
		}
		seq = ntohl(tcph->th_seq);
		ack = ntohl(tcph->th_ack);
		packet_len = ntohs(iph->ip_len); // TODO: calculate payload len instead ...
	}

	bool isTCP() { return is_tcp; }

	inline FlowKey* getFlowKey() const
	{
		return (FlowKey*)data;
	}

	void reset()
	{
		memset(data,0,sizeof(data));
	}

	bool operator<(const TcpFlowKey& other) const 
	{
		return memcmp(data, other.data, len)<0?true:false;
	}
	
	uint32_t seq;
	uint32_t ack;
	uint16_t packet_len;
private:
	bool is_tcp;
};

#endif
