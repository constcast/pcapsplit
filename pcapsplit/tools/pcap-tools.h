//  Copyright (C) 2010 Lothar Braun <lothar@lobraun.de>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifndef _PCAP_TOOLS_H_
#define _PACP_TOOLS_H_

#include <pcap.h>

struct dumper_tool {
	pcap_t* out_descriptor;
	pcap_dumper_t* dumper;	
};

struct dumper_tool* dumper_tool_open_file(const char* filename, int linktype);
int dumper_tools_close_file(struct dumper_tool** dumper);

#endif
