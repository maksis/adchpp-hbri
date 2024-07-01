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

#include "adchpp.h"

#include "ClientManager.h"

#include "Core.h"
#include "File.h"
#include "Client.h"
#include "LogManager.h"
#include "SocketManager.h"
#include "TigerHash.h"
#include "Encoder.h"
#include "version.h"

#include <codecvt>
#include <locale>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include <boost/range/algorithm/find.hpp>
#include <boost/range/algorithm/find_if.hpp>
#include <boost/range/algorithm/remove_if.hpp>
#include <boost/range/adaptor/map.hpp>

using boost::adaptors::map_values;
using boost::range::find;
using boost::range::find_if;

namespace adchpp {

using namespace std;

const string ClientManager::className = "ClientManager";

ClientManager::ClientManager(Core &core) throw() :
core(core),
hub(*this),
maxCommandSize(16 * 1024),
logTimeout(30 * 1000),
hbriTimeout(5000)
{
	core.getSocketManager().addTimedJob(1000, std::bind(&ClientManager::onTimerSecond, this));
}

void ClientManager::prepareSupports(bool addHbri) {
	hub.addSupports(AdcCommand::toFourCC("BASE"));
	hub.addSupports(AdcCommand::toFourCC("TIGR"));

	if (addHbri)
		hub.addSupports(AdcCommand::toFourCC("HBRI"));
}

void ClientManager::onTimerSecond() {
	// HBRI
	auto timeoutHbri = time::now() - time::millisec(hbriTimeout);
	for (auto i = hbriTokens.begin(); i != hbriTokens.end();) {
		if (timeoutHbri > i->second.second) {
			auto cc = dynamic_cast<Client*>(i->second.first);
			i = hbriTokens.erase(i);

			dcdebug("ClientManager: HBRI timeout in state %d\n", cc->getState());

			std::string proto = cc->isV6() ? "IPv4" : "IPv6";
			AdcCommand sta(AdcCommand::SEV_RECOVERABLE, AdcCommand::ERROR_HBRI_TIMEOUT, proto + " validation timed out");
			cc->send(sta);

			cc->unsetFlag(Entity::FLAG_VALIDATE_HBRI);
			cc->stripProtocolSupports();
			if (cc->getState() == Entity::STATE_HBRI)
				enterNormal(*cc, true, true);
		} else {
			i++;
		}
	}

	// Logins
	auto timeoutLogin = time::now() - time::millisec(getLogTimeout());
	while (!logins.empty() && (timeoutLogin > logins.front().second)) {
		auto cc = logins.front().first;

		dcdebug("ClientManager: Login timeout in state %d\n", cc->getState());
		cc->disconnect(Util::REASON_LOGIN_TIMEOUT);
		logins.pop_front();
	}
}

Bot* ClientManager::createBot(const Bot::SendHandler& handler) {
	Bot* ret = new Bot(*this, makeSID(), handler);
	return ret;
}

void ClientManager::regBot(Bot& bot) {
	enterIdentify(bot, false);
	enterNormal(bot, false, true);
	cids.insert(make_pair(bot.getCID(), &bot));
	nicks.insert(make_pair(bot.getField("NI"), &bot));
}

void ClientManager::send(const AdcCommand& cmd) throw() {
	if(cmd.getPriority() == AdcCommand::PRIORITY_IGNORE) {
		return;
	}

	bool all = false;
	switch(cmd.getType()) {
	case AdcCommand::TYPE_BROADCAST:
		all = true; // Fallthrough
	case AdcCommand::TYPE_FEATURE: {
		for(EntityIter i = entities.begin(); i != entities.end(); ++i) {
			if(all || !i->second->isFiltered(cmd.getFeatures())) {
				maybeSend(*i->second, cmd);
			}
		}
	}
		break;
	case AdcCommand::TYPE_DIRECT: // Fallthrough
	case AdcCommand::TYPE_ECHO: {
		Entity* e = getEntity(cmd.getTo());
		if(e) {
			maybeSend(*e, cmd);

			if(cmd.getType() == AdcCommand::TYPE_ECHO) {
				e = getEntity(cmd.getFrom());
				if(e) {
					maybeSend(*e, cmd);
				}
			}
		}
	}
		break;
	}
}

void ClientManager::maybeSend(Entity& c, const AdcCommand& cmd) {
	bool ok = true;
	signalSend_(c, cmd, ok);
	if(ok) {
		c.send(cmd);
	}
}

void ClientManager::sendToAll(const BufferPtr& buf) throw() {
	for(EntityIter i = entities.begin(); i != entities.end(); ++i) {
		i->second->send(buf);
	}
}

size_t ClientManager::getQueuedBytes() throw() {
	size_t total = 0;

	for(EntityIter i = entities.begin(); i != entities.end(); ++i) {
		total += i->second->getQueuedBytes();
	}

	return total;
}

void ClientManager::sendTo(const BufferPtr& buffer, uint32_t to) {
	EntityIter i = entities.find(to);
	if(i != entities.end()) {
		i->second->send(buffer);
	}
}

void ClientManager::handleIncoming(const ManagedSocketPtr& socket) throw() {
	Client::create(*this, socket, makeSID());
}

uint32_t ClientManager::makeSID() {
	while(true) {
		union {
			uint32_t sid;
			char chars[4];
		} sid;
		sid.chars[0] = Encoder::base32Alphabet[Util::rand(sizeof(Encoder::base32Alphabet))];
		sid.chars[1] = Encoder::base32Alphabet[Util::rand(sizeof(Encoder::base32Alphabet))];
		sid.chars[2] = Encoder::base32Alphabet[Util::rand(sizeof(Encoder::base32Alphabet))];
		sid.chars[3] = Encoder::base32Alphabet[Util::rand(sizeof(Encoder::base32Alphabet))];
		if(sid.sid != 0 && entities.find(sid.sid) == entities.end()) {
			return sid.sid;
		}
	}
}

void ClientManager::onConnected(Client& c) throw() {
	dcdebug("%s connected\n", AdcCommand::fromSID(c.getSID()).c_str());

	logins.push_back(make_pair(&c, time::now()));

	signalConnected_(c);
}

void ClientManager::onReady(Client& c) throw() {
	dcdebug("%s ready\n", AdcCommand::fromSID(c.getSID()).c_str());
	signalReady_(c);
}

void ClientManager::onReceive(Entity& c, AdcCommand& cmd) throw() {
	if(c.isSet(Entity::FLAG_GHOST)) {
		return;
	}

	if(!(cmd.getType() == AdcCommand::TYPE_BROADCAST || cmd.getType() == AdcCommand::TYPE_DIRECT || cmd.getType()
		== AdcCommand::TYPE_ECHO || cmd.getType() == AdcCommand::TYPE_FEATURE || cmd.getType() == AdcCommand::TYPE_HUB))
	{
		disconnect(c, Util::REASON_INVALID_COMMAND_TYPE, "Invalid command type");
		return;
	}

	bool ok = true;
	signalReceive_(c, cmd, ok);

	if(ok) {
		if(!dispatch(c, cmd)) {
			return;
		}
	}

	send(cmd);
}

void ClientManager::onBadLine(Client& c, const string& aLine) throw() {
	if(c.isSet(Entity::FLAG_GHOST)) {
		return;
	}

	signalBadLine_(c, aLine);
}

void ClientManager::badState(Entity& c, const AdcCommand& cmd) throw() {
	disconnect(c, Util::REASON_BAD_STATE, "Invalid state for command", AdcCommand::ERROR_BAD_STATE, "FC" + cmd.getFourCC());
}

bool ClientManager::handleDefault(Entity& c, AdcCommand& cmd) throw() {
	if(c.getState() != Entity::STATE_NORMAL) {
		badState(c, cmd);
		return false;
	}
	return true;
}

bool ClientManager::handle(AdcCommand::SUP, Entity& c, AdcCommand& cmd) throw() {
	if(!verifySUP(c, cmd)) {
		return false;
	}

	if(c.getState() == Entity::STATE_PROTOCOL) {
		enterIdentify(c, true);
	} else if(c.getState() != Entity::STATE_NORMAL) {
		badState(c, cmd);
		return false;
	}

	return true;
}

bool ClientManager::verifySUP(Entity& c, AdcCommand& cmd) throw() {
	c.updateSupports(cmd);

	if(!c.hasSupport(AdcCommand::toFourCC("BASE"))) {
		disconnect(c, Util::REASON_NO_BASE_SUPPORT, "This hub requires BASE support");
		return false;
	}

	if(!c.hasSupport(AdcCommand::toFourCC("TIGR"))) {
		disconnect(c, Util::REASON_NO_TIGR_SUPPORT, "This hub requires TIGR support");
		return false;
	}

	return true;
}

bool ClientManager::verifyINF(Entity& c, AdcCommand& cmd) throw() {
	if (!verifyCID(c, cmd))
		return false;

	if (!verifyNick(c, cmd))
		return false;

	if (cmd.getParam("DE", 0, strtmp)) {
		if (!Util::validateCharset(strtmp, 32)) {
			disconnect(c, Util::REASON_INVALID_DESCRIPTION, "Invalid character in description");
			return false;
		}
	}

	Client* cc = dynamic_cast<Client*>(&c);

	if(cc) {
		if(!verifyIp(*cc, cmd, false))
			return false;
	}

	c.updateFields(cmd);

	string tmp;
	if (cmd.getParam("SU", 0, tmp) && !c.isSet(Entity::FLAG_VALIDATE_HBRI) && c.getState() != Entity::STATE_HBRI)
		c.stripProtocolSupports();

	return true;
}

bool ClientManager::verifyPassword(Entity& c, const string& password, const ByteVector& salt,
				   const string& suppliedHash, TigerHash&& tiger) {
	tiger.update(&password[0], password.size());
	tiger.update(&salt[0], salt.size());
	uint8_t tmp[TigerHash::BYTES];
	Encoder::fromBase32(suppliedHash.c_str(), tmp, TigerHash::BYTES);
	if(memcmp(tiger.finalize(), tmp, TigerHash::BYTES) == 0) {
		return true;
	}

	return false;
}

bool ClientManager::verifyPassword(Entity& c, const string& password, const ByteVector& salt,
				   const string& suppliedHash) {
	return verifyPassword(c, password, salt, suppliedHash, TigerHash());
}

bool ClientManager::verifyHashedPassword(Entity& c, const ByteVector& hashedPassword, int64_t hashedPasswordLen,
					 const ByteVector& salt, const string& suppliedHash) {
	// hashedPassword must be in little-endian order; this code itself is endian-independent.
	uint64_t initial_res[TigerHash::BYTES/8];
	for (auto i = 0; i < 3; ++i) {
	    initial_res[i] = 0;
	    for (auto j = 0; j < 8; ++j)
		initial_res[i] = initial_res[i] * 256 + hashedPassword[8*i+(7-j)];
	}
	return verifyPassword(c, "", salt, suppliedHash, TigerHash(hashedPasswordLen, initial_res));
}

bool ClientManager::verifyOverflow(Entity& c) {
	size_t overflowing = 0;
	for(EntityIter i = entities.begin(), iend = entities.end(); i != iend; ++i) {
		if(!i->second->getOverflow().is_not_a_date_time()) {
			overflowing++;
		}
	}

	if(overflowing > 3 && overflowing > (entities.size() / 4)) {
		disconnect(c, Util::REASON_NO_BANDWIDTH, "Not enough bandwidth available, please try again later", AdcCommand::ERROR_HUB_FULL, Util::emptyString, 1);
		return false;
	}

	return true;
}

bool ClientManager::sendHBRI(Entity& c) {
	if (c.hasSupport(AdcCommand::toFourCC("HBRI"))) {
		AdcCommand cmd(AdcCommand::CMD_TCP);
		if (!dynamic_cast<Client*>(&c)->getHbriParams(cmd)) {
			return false;
		}

		c.setFlag(Entity::FLAG_VALIDATE_HBRI);
		if (c.getState() != Entity::STATE_NORMAL)
			c.setState(Entity::STATE_HBRI);

		auto token = Util::toString(Util::rand());
		hbriTokens.insert(make_pair(token, make_pair(&c, time::now())));
		dcdebug("HBRI: request validation (token %s)\n", token.c_str());

		cmd.addParam("TO", token);
		c.send(cmd);
		return true;
	}

	return false;
}

bool ClientManager::handle(AdcCommand::INF, Entity& c, AdcCommand& cmd) throw() {
	if(c.getState() != Entity::STATE_IDENTIFY && c.getState() != Entity::STATE_NORMAL) {
		badState(c, cmd);
		return false;
	}

	if(!verifyINF(c, cmd))
		return false;

	if(c.getState() == Entity::STATE_IDENTIFY) {
		if(!verifyOverflow(c)) {
			return false;
		}

		enterNormal(c, true, true);
		return false;
	}

	return true;
}

static const int allowedCount = 3;
static const char* allowedV4[allowedCount] = { "I4", "U4", "SU" };
static const char* allowedV6[allowedCount] = { "I6", "U6", "SU" };
bool ClientManager::handle(AdcCommand::TCP, Entity& c, AdcCommand& cmd) throw() {
	dcdebug("Received HBRI TCP: %s", cmd.toString().c_str());
	
	string error;
	string token;
	if(cmd.getParam("TO", 0, token)) {
		auto p = hbriTokens.find(token);
		if (p != hbriTokens.end()) {
			Client* mainCC = dynamic_cast<Client*>(p->second.first);
			mainCC->unsetFlag(Entity::FLAG_VALIDATE_HBRI);

			if (mainCC->getState() != Entity::STATE_HBRI && mainCC->getState() != Entity::STATE_NORMAL) {
				badState(c, cmd);
				return false;
			}

			hbriTokens.erase(p);

			if (!verifyIp(*dynamic_cast<Client*>(&c), cmd, true))
				return false;

			// disconnect the validation connection
			AdcCommand sta(AdcCommand::SEV_SUCCESS, AdcCommand::SUCCESS, "Validation succeed");
			c.send(sta);
			c.disconnect(Util::REASON_HBRI);

			// remove extra parameters
			auto& params = cmd.getParameters();
			const auto& allowed = dynamic_cast<Client*>(&c)->isV6() ? allowedV6 : allowedV4;

			params.erase(boost::remove_if(params, [&](const string& s) {
				return find(allowed, allowed + allowedCount, s.substr(0, 2)) == &allowed[allowedCount];
			}), params.end());

			// update the fields for the main entity
			mainCC->updateFields(cmd);

			if (mainCC->getState() == Entity::STATE_HBRI) {
				// continue with the normal login
				enterNormal(*mainCC, true, true);
			} else {
				// send the updated fields
				AdcCommand inf(AdcCommand::CMD_INF, AdcCommand::TYPE_BROADCAST, mainCC->getSID());
				inf.getParameters() = cmd.getParameters();
				sendToAll(inf.getBuffer());
			}
			return true;
		} else {
			dcdebug("HBRI TCP: unknown validation token %s\n", token.c_str());
			error = "Unknown validation token";
		}
	} else {
		dcdebug("HBRI TCP: validation token missing\n");
		error = "Validation token missing";
	}

	dcassert(!error.empty());
	AdcCommand sta(AdcCommand::SEV_FATAL, AdcCommand::ERROR_LOGIN_GENERIC, error);
	c.send(sta);

	c.disconnect(Util::REASON_HBRI);
	return true;
}

bool ClientManager::verifyIp(Client& c, AdcCommand& cmd, bool isHbriConn) throw() {
	if(c.isSet(Entity::FLAG_OK_IP))
		return true;

	using namespace boost::asio::ip;

    address remoteAddress;

    try { 
		remoteAddress = address::from_string(c.getIp());
	} catch(const boost::system::system_error&) {
		printf("Error when reading IP %s\n", c.getIp().c_str());
		return false;
    }

	std::string ip;

	bool doValidation = false;
	if (!c.isV6()) {
		auto v4 = remoteAddress.is_v4() ? remoteAddress.to_v4() : remoteAddress.to_v6().to_v4();

		if (cmd.getParam("I4", 0, ip)) {
			// Validate IPv4
			dcdebug("%s verifying IP %s\n", AdcCommand::fromSID(c.getSID()).c_str(), ip.c_str());
			if (ip.empty() || address_v4::from_string(ip) == address_v4::any()) {
				cmd.delParam("I4", 0);
				cmd.addParam("I4", c.getIp());
			} else if(address_v4::from_string(ip) != v4 && !Util::isPrivateIp(c.getIp(), false)) {
				disconnect(c, Util::REASON_INVALID_IP, "Your IP is " + c.getIp() +
					", reconfigure your client settings", AdcCommand::ERROR_BAD_IP, "IP" + c.getIp());
				return false;
			}
		} else if (!isHbriConn) {
			// Nothing was provided
			c.setField("I4", v4.to_string());
		}

		// Handle IPv6
		string v6Ip;
		doValidation = !isHbriConn && cmd.getParam("I6", 0, v6Ip) && !v6Ip.empty();

		// Keep the secondary IP (if there is one) for local users
		if (v6Ip.empty() || address_v6::from_string(v6Ip) == address_v6::any() || !Util::isPrivateIp(c.getIp(), false)) {
			cmd.delParam("U6", 0);
			cmd.delParam("I6", 0);
		}
	} else {
		if (cmd.getParam("I6", 0, ip)) {
			// Validate IPv6
			dcdebug("%s verifying IPv6 %s\n", AdcCommand::fromSID(c.getSID()).c_str(), ip.c_str());
			if (ip.empty() || address_v6::from_string(ip) == address_v6::any()) {
				cmd.delParam("I6", 0);
				cmd.addParam("I6", c.getIp());
			} else if(address_v6::from_string(ip) != remoteAddress.to_v6() && !Util::isPrivateIp(c.getIp(), true)) {
				disconnect(c, Util::REASON_INVALID_IP, "Your IP is " + c.getIp() +
					", reconfigure your client settings", AdcCommand::ERROR_BAD_IP, "IP" + c.getIp());
				return false;
			}
		} else if (!isHbriConn) {
			// Nothing was provided
			c.setField("I6", c.getIp());
		}

		{
			// Handle IPv4
			string v4Ip;
			doValidation = !isHbriConn && cmd.getParam("I4", 0, v4Ip) && !v4Ip.empty();

			// Keep the secondary IP (if there is one) for local users
			if (v4Ip.empty() || address_v4::from_string(v4Ip) == address_v4::any() || !Util::isPrivateIp(c.getIp(), true)) {
				cmd.delParam("I4", 0);
				cmd.delParam("U4", 0);
			}
		}
	}

	if (doValidation) {
		if (c.getState() == Entity::STATE_NORMAL) {
			// Connected user with new params, perform new validation
			sendHBRI(c);
		} else {
			// Connecting user, handle validation later
			c.setFlag(Entity::FLAG_VALIDATE_HBRI);
		}
	}

	return true;
}

bool ClientManager::verifyCID(Entity& c, AdcCommand& cmd) throw() {
	if(cmd.getParam("ID", 0, strtmp)) {
		dcdebug("%s verifying CID %s\n", AdcCommand::fromSID(c.getSID()).c_str(), strtmp.c_str());
		if(c.getState() != Entity::STATE_IDENTIFY) {
			disconnect(c, Util::REASON_CID_CHANGE, "CID changes not allowed");
			return false;
		}

		if(strtmp.size() != CID::BASE32_SIZE) {
			disconnect(c, Util::REASON_PID_CID_LENGTH, "Invalid CID length");
			return false;
		}

		CID cid(strtmp);

		strtmp.clear();

		if(!cmd.getParam("PD", 0, strtmp)) {
			disconnect(c, Util::REASON_PID_MISSING, "PID missing", AdcCommand::ERROR_INF_MISSING, "FLPD");
			return false;
		}

		if(strtmp.size() != CID::BASE32_SIZE) {
			disconnect(c, Util::REASON_PID_CID_LENGTH, "Invalid PID length");
			return false;
		}

		CID pid(strtmp);

		TigerHash th;
		th.update(pid.data(), CID::SIZE);
		if(!(CID(th.finalize()) == cid)) {
			disconnect(c, Util::REASON_PID_CID_MISMATCH, "PID does not correspond to CID", AdcCommand::ERROR_INVALID_PID);
			return false;
		}

		auto other = cids.find(cid);
		if(other != cids.end()) {
			// disconnect the ghost
			disconnect(*other->second, Util::REASON_CID_TAKEN, "CID taken", AdcCommand::ERROR_CID_TAKEN);
			removeEntity(*other->second, Util::REASON_CID_TAKEN, Util::emptyString);
		}

		c.setCID(cid);

		cids.insert(make_pair(c.getCID(), &c));
		cmd.delParam("PD", 0);
	}

	if(cmd.getParam("PD", 0, strtmp)) {
		disconnect(c, Util::REASON_PID_WITHOUT_CID, "CID required when sending PID");
		return false;
	}

	return true;
}

namespace {
bool validateNickF(wchar_t c) { /// @todo lambda

	// the following are explicitly allowed (isprint sometimes differs)
	if(c >= L'\u2100' && c <= L'\u214F' /* letter-like symbols */) {
		return false;
	}

	// the following are explicitly disallowed (isprint sometimes differs)
	if(c == L'\u00AD' /* soft hyphen */) {
		return true;
	}

	return !std::iswprint(c);
}

bool validateNick(const string& nick) {
	if(!Util::validateCharset(nick, 33)) { // chars < 33 forbidden (including the space char)
		return false;
	}

	// avoid impersonators
	std::wstring nickW =
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(nick);
	if(std::find_if(nickW.begin(), nickW.end(), validateNickF) != nickW.end()) {
		return false;
	}

	return true;
}
}

bool ClientManager::verifyNick(Entity& c, const AdcCommand& cmd) throw() {
	if(cmd.getParam("NI", 0, strtmp)) {
		dcdebug("%s verifying nick %s\n", AdcCommand::fromSID(c.getSID()).c_str(), strtmp.c_str());
		
		if(!validateNick(strtmp)) {
			disconnect(c, Util::REASON_NICK_INVALID, "Invalid character in nick", AdcCommand::ERROR_NICK_INVALID);
			return false;
		}

		const string& oldNick = c.getField("NI");
		if(!oldNick.empty())
			nicks.erase(oldNick);

		if(nicks.find(strtmp) != nicks.end()) {
			disconnect(c, Util::REASON_NICK_TAKEN, "Nick taken, please pick another one", AdcCommand::ERROR_NICK_TAKEN);
			return false;
		}

		nicks.insert(make_pair(strtmp, &c));
	}

	return true;
}

void ClientManager::setState(Entity& c, Entity::State newState) throw() {
	Entity::State oldState = c.getState();
	c.setState(newState);
	signalState_(c, oldState);
}

void ClientManager::disconnect(Entity& c, Util::Reason reason, const std::string& info, AdcCommand::Error error, const std::string& staParam, int aReconnectTime) {
	// send a fatal STA
	AdcCommand sta(AdcCommand::SEV_FATAL, error, info);
	if(!staParam.empty())
		sta.addParam(staParam);
	c.send(sta);

	// send a QUI
	c.send(AdcCommand(AdcCommand::CMD_QUI).addParam(AdcCommand::fromSID(c.getSID()))
		.addParam("DI", "1").addParam("MS", info).addParam("TL", Util::toString(aReconnectTime)));

	c.disconnect(reason);
}

void ClientManager::enterIdentify(Entity& c, bool sendData) throw() {
	dcassert(c.getState() == Entity::STATE_PROTOCOL);
	dcdebug("%s entering IDENTIFY\n", AdcCommand::fromSID(c.getSID()).c_str());
	if(sendData) {
		c.send(hub.getSUP());
		c.send(AdcCommand(AdcCommand::CMD_SID).addParam(AdcCommand::fromSID(c.getSID())));
		c.send(hub.getINF());
	}

	setState(c, Entity::STATE_IDENTIFY);
}

ByteVector ClientManager::enterVerify(Entity& c, bool sendData) throw() {
	dcassert(c.getState() == Entity::STATE_IDENTIFY);
	dcdebug("%s entering VERIFY\n", AdcCommand::fromSID(c.getSID()).c_str());

	ByteVector challenge;
	challenge.reserve(32);
	for(int i = 0; i < 32 / 4; ++i) {
		uint32_t r = Util::rand();
		challenge.insert(challenge.end(), (uint8_t*) &r, 4 + (uint8_t*) &r);
	}

	if(sendData) {
		c.send(AdcCommand(AdcCommand::CMD_GPA).addParam(Encoder::toBase32(&challenge[0], challenge.size())));
	}

	setState(c, Entity::STATE_VERIFY);
	return challenge;
}

bool ClientManager::enterNormal(Entity& c, bool sendData, bool sendOwnInf) throw() {
	if (c.isSet(Entity::FLAG_VALIDATE_HBRI)) {
		if (sendHBRI(c)) {
			return false;
		}

		c.unsetFlag(Entity::FLAG_VALIDATE_HBRI);
	}

	dcassert(c.getState() == Entity::STATE_IDENTIFY || c.getState() == Entity::STATE_VERIFY);
	dcdebug("%s entering NORMAL\n", AdcCommand::fromSID(c.getSID()).c_str());

	if(sendData) {
		for(EntityIter i = entities.begin(); i != entities.end(); ++i) {
			c.send(i->second->getINF());
		}
	}

	if(sendOwnInf) {
		sendToAll(c.getINF());
		if(sendData) {
			c.send(c.getINF());
		}
	}

	removeLogins(c);

	entities.insert(make_pair(c.getSID(), &c));

	setState(c, Entity::STATE_NORMAL);
	return true;
}

void ClientManager::removeLogins(Entity& e) throw() {
	Client* c = dynamic_cast<Client*>(&e);
	if(!c) {
		return;
	}

	{
		auto i = find_if(logins.begin(), logins.end(), CompareFirst<Client*, time::ptime>(c));
		if (i != logins.end()) {
			logins.erase(i);
		}
	}

	if (e.hasSupport(AdcCommand::toFourCC("HBRI"))) {
		auto i = find_if(hbriTokens | map_values, CompareFirst<Entity*, time::ptime>(c)).base();
		if (i != hbriTokens.end()) {
			hbriTokens.erase(i);
		}
	}
}

void ClientManager::removeEntity(Entity& c, Util::Reason reason, const std::string &info) throw() {
	if(c.isSet(Entity::FLAG_GHOST))
		return;

	dcdebug("Removing %s - %s\n", AdcCommand::fromSID(c.getSID()).c_str(), c.getCID().toBase32().c_str());
	c.setFlag(Entity::FLAG_GHOST);

	signalDisconnected_(c, reason, info);

	if(c.getState() == Entity::STATE_NORMAL) {
		entities.erase(c.getSID());
		sendToAll(AdcCommand(AdcCommand::CMD_QUI).addParam(AdcCommand::fromSID(c.getSID())).addParam("DI", "1").getBuffer());
	} else {
		removeLogins(c);
	}

	nicks.erase(c.getField("NI"));
	cids.erase(c.getCID());
}

Entity* ClientManager::getEntity(uint32_t aSid) throw() {
	switch(aSid) {
	case AdcCommand::INVALID_SID: return nullptr;
	case AdcCommand::HUB_SID: return &hub;
	default:
		{
			EntityIter i = entities.find(aSid);
			return (i == entities.end()) ? nullptr : i->second;
		}
	}
}

uint32_t ClientManager::getSID(const string& aNick) const throw() {
	NickMap::const_iterator i = nicks.find(aNick);
	return (i == nicks.end()) ? AdcCommand::INVALID_SID : i->second->getSID();
}

uint32_t ClientManager::getSID(const CID& cid) const throw() {
	CIDMap::const_iterator i = cids.find(cid);
	return (i == cids.end()) ? AdcCommand::INVALID_SID : i->second->getSID();
}

void ClientManager::onFailed(Client& c, Util::Reason reason, const std::string &info) throw() {
	removeEntity(c, reason, info);
}

}