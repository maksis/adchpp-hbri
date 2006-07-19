/* 
 * Copyright (C) 2006 Jacek Sieka, arnetheduck on gmail point com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef SERVERSOCKET_H
#define SERVERSOCKET_H

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "Socket.h"

class ServerSocket {
public:
	void listen(short aPort) throw(SocketException);
	ServerSocket() throw() : sock(INVALID_SOCKET) { }

	~ServerSocket() throw() {
		disconnect();
	}
	
	void disconnect() {
		if(sock != INVALID_SOCKET) {
			closesocket(sock);
			sock = INVALID_SOCKET;
		}
	}

	bool isReady() const;
	socket_t getSocket() const { return sock; }
private:
	// No copies
	ServerSocket(const ServerSocket&);
	ServerSocket& operator=(const ServerSocket&);

	socket_t sock;
};

#endif // SERVERSOCKET_H
