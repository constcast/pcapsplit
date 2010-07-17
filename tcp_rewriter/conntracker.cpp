#include "conntracker.h"

#include <netinet/tcp.h>

#include <iostream>
#include <algorithm>

uint32_t ConnTracker::start_seq = 0;

bool ConnTracker::compare_seq(const ConnPacket& l, const ConnPacket& r)
{
	if ((l.seq >= start_seq && r.seq >= start_seq) || (l.seq < start_seq && r.seq < start_seq))
		return l.seq < r.seq;
	else if (l.seq < start_seq && r.seq >= start_seq)
		return true;
	else if (r.seq < start_seq && l.seq >= start_seq)
		return false;

	// we should never get here
	std::cerr << "ConnTracker::compare_seq logical error detected! start_seq == " << start_seq
		  << " l.seq == " << l.seq << " r.seq == " << r.seq << std::endl;
	return true;
}

ConnTracker::ConnTracker()
{

}

	
void ConnTracker::addPacket(const uint8_t* packetData, struct pcap_pkthdr* packetHeader)
{
	static uint64_t id = 0;
	TcpFlowKey key(packetData);
	if (!key.isTCP()) 
		return;

	ConnPacket connPacket;
	connPacket.id = id;
	connPacket.seq = key.seq;
	connPacket.ack = key.ack;
	connPacket.len = key.packet_len;

	connList[key].push_back(connPacket);
	id++;
}

void ConnTracker::reorder()
{
	int connCounter = 1;
	for (ConnList::iterator i = connList.begin(); i != connList.end(); ++i) {
		std::cout << "Reordering flow " << connCounter << "..." << std::endl;
		reorderConnection(i->second);
		++connCounter;
	}
}

void ConnTracker::reorderConnection(PacketList& pList)
{
	// TODO: find SYN-paket to extract start_seq from
	start_seq = pList.begin()->seq;
	std::sort(pList.begin(), pList.end(), compare_seq);
}

void ConnTracker::removeDuplicates()
{
	int connCounter = 1;
	for (ConnList::iterator i = connList.begin(); i != connList.end(); ++i) {
		std::cout << "Removing duplicates from flow " << connCounter << "..." << std::endl;
		reorderConnection(i->second);
		++connCounter;
	}

}

void ConnTracker::removeDuplicatesFromConnection(PacketList& pList)
{
	size_t i = 1;
	size_t prev = 0;
	while (i <= pList.size()) {
		if (pList[prev] == pList[i]) {
			pList.erase(pList.begin() + i);
		} else {
			++prev;
			++i;
		}
	}
}

void ConnTracker::generateOutputList()
{
	uint64_t outId = 0;
	ConnList::iterator i;
	while (connList.size() != 0) {
		i = connList.begin();
		TcpFlowKey reverseKey;
		reverseKey.reverse(i->first);
		ConnList::iterator j = connList.find(reverseKey);
		if (j == connList.end()) {
			// only one side of the connection was seen
			for (PacketList::iterator k = i->second.begin(); k != i->second.end(); ++k)
				outputList.push_back(*k);
			connList.erase(i);
		} else {
			size_t fside = 0;
			size_t bside = 0;
			PacketList& front = i->second;
			PacketList& back =  j->second;
			uint32_t fsseq = front[0].seq;
			uint32_t fsack = front[0].ack;
			uint32_t bsseq = back[0].seq;
			uint32_t bsack = back[0].ack;
			while (fside < front.size() && bside < back.size()) {
				if (front[fside].seq < back[bside].ack) {
					outputList.push_back(front[fside]);
					++fside;
				} else if (front[fside].seq == back[bside].ack) {
					//if (front[fside].ack 
				} else {
					outputList.push_back(back[bside]);
					++bside;
				}
			}
		}
	}
}
