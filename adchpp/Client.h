/*
 * Copyright (C) 2006-2018 Jacek Sieka, arnetheduck on gmail point com
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

#ifndef ADCHPP_CLIENT_H
#define ADCHPP_CLIENT_H

#include "common.h"

#include "ManagedSocket.h"
#include "FastAlloc.h"
#include "AdcCommand.h"
#include "CID.h"
#include "Entity.h"

namespace adchpp {

/**
 * The client represents one connection to a user.
 */
class ADCHPP_VISIBLE Client : public Entity, public FastAlloc<Client> {
public:
	static Client* create(ClientManager &cm, const ManagedSocketPtr& ms_, uint32_t sid_) noexcept;

	using Entity::send;

	virtual void send(const BufferPtr& command) { socket->write(command); }

	/** @param reason The statistic to update */
	ADCHPP_DLL virtual void disconnect(Util::Reason reason, const std::string &info = Util::emptyString) noexcept;
	const std::string& getIp() const noexcept { return socket->getIp(); }
	bool getHbriParams(AdcCommand& cmd) const noexcept { return socket->getHbriParams(cmd); }
	bool isV6() const { return socket->isV6(); }

	/**
	 * Set data mode for aBytes bytes.
	 * May only be called from on(ClientListener::Command...).
	 */
	typedef std::function<void (Client&, const uint8_t*, size_t)> DataFunction;
	void setDataMode(const DataFunction& handler, int64_t aBytes) { dataHandler = handler; dataBytes = aBytes; }

	virtual size_t getQueuedBytes() const { return socket->getQueuedBytes(); }
	virtual time::ptime getOverflow() const { return socket->getOverflow(); }

private:
	Client(ClientManager &cm, uint32_t sid_) noexcept;
	virtual ~Client();

	bool disconnecting;

	BufferPtr buffer;
	ManagedSocketPtr socket;
	int64_t dataBytes;

	DataFunction dataHandler;
	void setSocket(const ManagedSocketPtr& aSocket) noexcept;

	void onConnected() noexcept;
	void onReady() noexcept;
	void onData(const BufferPtr&) noexcept;
	void onFailed(Util::Reason reason, const std::string &info) noexcept;

};

}

#endif // CLIENT_H
