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

#include "SocketManager.h"

#include "ClientManager.h"
#include "LogManager.h"
#include "ManagedSocket.h"
#include "ServerInfo.h"
#include "SimpleXML.h"
#include "Core.h"

#ifdef HAVE_OPENSSL
#include <boost/asio/ssl.hpp>
#endif

#include <boost/date_time/posix_time/time_parsers.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/v6_only.hpp>

namespace adchpp {

using namespace std;
using namespace std::placeholders;
using namespace boost::asio;
using boost::system::error_code;
using boost::system::system_error;

SocketManager::SocketManager(Core &core) :
core(core),
bufferSize(1024),
maxBufferSize(16 * 1024),
overflowTimeout(60 * 1000),
disconnectTimeout(10 * 1000),
hasV4Address(false),
hasV6Address(false)
{
}

const string SocketManager::className = "SocketManager";

template<typename T>
class SocketStream : public AsyncStream {
public:
	template<typename X>
	SocketStream(X& x) : sock(x) { }

	template<typename X, typename Y>
	SocketStream(X& x, Y& y) : sock(x, y) { }

	~SocketStream() { dcdebug("SocketStream deleted\n"); }

	virtual size_t available() {
		return sock.lowest_layer().available();
	}

	virtual void setOptions(size_t bufferSize) {
		sock.lowest_layer().set_option(socket_base::receive_buffer_size((int)bufferSize));
		sock.lowest_layer().set_option(socket_base::send_buffer_size((int)bufferSize));
	}

	virtual std::string getIp() {
		try { return sock.lowest_layer().remote_endpoint().address().to_string(); }
		catch(const system_error&) { return Util::emptyString; }
	}

	virtual void prepareRead(const BufferPtr& buf, const Handler& handler) {
		if(buf) {
			sock.async_read_some(buffer(buf->data(), buf->size()), handler);
		} else {
			sock.async_read_some(null_buffers(), handler);
		}
	}

	virtual size_t read(const BufferPtr& buf) {
		return sock.read_some(buffer(buf->data(), buf->size()));
	}

	virtual void write(const BufferList& bufs, const Handler& handler) {
		if(bufs.size() == 1) {
			sock.async_write_some(buffer(bufs[0]->data(), bufs[0]->size()), handler);
		} else {
			size_t n = std::min(bufs.size(), static_cast<size_t>(64));
			std::vector<const_buffer> buffers;
			buffers.reserve(n);

			const size_t maxBytes = 1024;

			for(size_t i = 0, total = 0; i < n && total < maxBytes; ++i) {
				size_t left = maxBytes - total;
				size_t bytes = min(bufs[i]->size(), left);
				buffers.push_back(const_buffer(bufs[i]->data(), bytes));
				total += bytes;
			}

			sock.async_write_some(buffers, handler);
		}
	}

	T sock;
};

class SimpleSocketStream : public SocketStream<ip::tcp::socket> {
	typedef SocketStream<ip::tcp::socket> Stream;

	struct ShutdownHandler {
		ShutdownHandler(const Handler& h) : h(h) { }
		void operator()() { error_code ec; h(ec, 0); }
		Handler h;
	};

public:
	SimpleSocketStream(boost::asio::io_service& x) : Stream(x) { }

	virtual void init(const std::function<void ()>& postInit) {
		postInit();
	}

	virtual void shutdown(const Handler& handler) {
		sock.shutdown(ip::tcp::socket::shutdown_send);
		sock.get_executor().execute(ShutdownHandler(handler));
	}

	virtual void close() {
		// Abortive close, just go away...
		if(sock.is_open()) {
			error_code ec;
			sock.close(ec); // Ignore errors
		}
	}
};

#ifdef HAVE_OPENSSL

class TLSSocketStream : public SocketStream<ssl::stream<ip::tcp::socket> > {
	typedef SocketStream<ssl::stream<ip::tcp::socket> > Stream;

	struct ShutdownHandler {
		ShutdownHandler(const Handler& h) : h(h) { }
		void operator()(const error_code &ec) { h(ec, 0); }
		Handler h;
	};

public:
	TLSSocketStream(io_service& x, ssl::context& y) : Stream(x, y) { }

	virtual void init(const std::function<void ()>& postInit) {
		sock.async_handshake(ssl::stream_base::server, std::bind(&TLSSocketStream::handleHandshake,
			this, std::placeholders::_1, postInit));
	}

	virtual void shutdown(const Handler& handler) {
		sock.async_shutdown(ShutdownHandler(handler));
	}

	virtual void close() {
		// Abortive close, just go away...
		if(sock.lowest_layer().is_open()) {
			error_code ec;
			sock.lowest_layer().close(ec); // Ignore errors
		}
	}

private:
	void handleHandshake(const error_code& ec, const std::function<void ()>& postInit) {
		if(!ec) {
			postInit();
		}
	}
};

#endif

static string formatEndpoint(const ip::tcp::endpoint& ep) {
	return (ep.address().is_v4() ? ep.address().to_string() + ':' : '[' + ep.address().to_string() + "]:")
		+ Util::toString(ep.port());
}

class SocketFactory : public enable_shared_from_this<SocketFactory>, boost::noncopyable {
public:
	SocketFactory(SocketManager& sm, const SocketManager::IncomingHandler& handler_, ServerInfoPtr& info, const ip::tcp::endpoint& endpoint) :
		sm(sm),
		acceptor(sm.io),
		handler(handler_),
		si(info)
	{
		acceptor.open(endpoint.protocol());
		acceptor.set_option(socket_base::reuse_address(true));
		if(endpoint.protocol() == ip::tcp::v6()) {
			acceptor.set_option(ip::v6_only(true));
		}

		auto a = endpoint.address().to_string();

		acceptor.bind(endpoint);
		acceptor.listen(socket_base::max_connections);

		LOGC(sm.getCore(), SocketManager::className,
			"Listening on " + formatEndpoint(endpoint) +
			" (Encrypted: " + (info->secure() ? "Yes)" : "No)"));

#ifdef HAVE_OPENSSL
		if(info->secure()) {
			context.reset(new ssl::context(ssl::context::tls));
			
			context->set_options(ssl::context::no_sslv2 | ssl::context::no_sslv3 | ssl::context::single_dh_use);
			//context->set_password_callback(boost::bind(&server::get_password, this));
			context->use_certificate_chain_file(info->TLSParams.cert);
			context->use_private_key_file(info->TLSParams.pkey, ssl::context::pem);
			context->use_tmp_dh_file(info->TLSParams.dh);
				
#if OPENSSL_VERSION_NUMBER >= 0x1000201fL
				SSL_CTX_set1_curves_list(context->native_handle(), "P-256");
#endif

			EC_KEY* tmp_ecdh;
			if ((tmp_ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) != NULL) {
				SSL_CTX_set_options(context->native_handle(), SSL_OP_SINGLE_ECDH_USE);
				SSL_CTX_set_tmp_ecdh(context->native_handle(), tmp_ecdh);

				EC_KEY_free(tmp_ecdh);
			}
		}
#endif
	}

	void prepareAccept() {
		if(!sm.work.get()) {
			return;
		}

#ifdef HAVE_OPENSSL
		if(context) {
			auto s = make_shared<TLSSocketStream>(sm.io, *context);
			auto socket = make_shared<ManagedSocket>(sm, s, si);
			acceptor.async_accept(s->sock.lowest_layer(), std::bind(&SocketFactory::handleAccept, shared_from_this(), std::placeholders::_1, socket));
		} else {
#endif
			auto s = make_shared<SimpleSocketStream>(sm.io);
			auto socket = make_shared<ManagedSocket>(sm, s, si);
			acceptor.async_accept(s->sock.lowest_layer(), std::bind(&SocketFactory::handleAccept, shared_from_this(), std::placeholders::_1, socket));
#ifdef HAVE_OPENSSL
		}
#endif
	}

	void handleAccept(const error_code& ec, const ManagedSocketPtr& socket) {
		if(!ec) {
			socket->sock->setOptions(sm.getBufferSize());
			auto ip = socket->sock->getIp();
			auto p = ip.find("%");
			socket->setIp(p != string::npos ? ip.substr(0, p) : ip);
		}

		completeAccept(ec, socket);

		prepareAccept();
	}

	void completeAccept(const error_code& ec, const ManagedSocketPtr& socket) {
		handler(socket);
		socket->completeAccept(ec);
	}

	void close() { acceptor.close(); }

	SocketManager &sm;
	ip::tcp::acceptor acceptor;
	SocketManager::IncomingHandler handler;
	ServerInfoPtr si;
#ifdef HAVE_OPENSSL
	unique_ptr<ssl::context> context;
#endif

};

void SocketManager::prepareProtocol(ServerInfoPtr& si, bool v6) {
	const string proto = v6 ? "IPv6" : "IPv4";
	try {
		using ip::tcp;
		tcp::resolver r(io);

		// Resolve the public address
		string& hubAddress = v6 ? si->address6 : si->address4;
		if (!hubAddress.empty()) {
			try {
				auto remote = r.resolve(tcp::resolver::query(v6 ? tcp::v6() : tcp::v4(), hubAddress, si->port,
					tcp::resolver::query::address_configured | tcp::resolver::query::passive));
				hubAddress = remote->endpoint().address().to_string();
				v6 ? hasV6Address = true : hasV4Address = true;
			} catch (const std::exception& e) {
				LOG(SocketManager::className, "Error when resolving the " + proto + " hub address " + hubAddress + ": " + e.what());
				hubAddress = Util::emptyString;
			}
		}

		// Resolve the bind address
		auto local = r.resolve(tcp::resolver::query(v6 ? tcp::v6() : tcp::v4(), v6 ? si->bind6 : si->bind4, si->port,
			tcp::resolver::query::address_configured | tcp::resolver::query::passive));

		for (auto i = local; i != tcp::resolver::iterator(); ++i) {
			auto factory = make_shared<SocketFactory>(*this, incomingHandler, si, *i);
			factory->prepareAccept();
			factories.push_back(factory);
		}
	} catch (const std::exception& e) {
		LOG(SocketManager::className, "Error while loading " + proto + " server on port " + si->port + ": " + e.what());
	}
}

int SocketManager::run() {
	//Sleep(10000);
	LOG(SocketManager::className, "Starting");

	work.reset(new io_service::work(io));

	for(auto i = servers.begin(), iend = servers.end(); i != iend; ++i) {
		auto& si = *i;
		bool listenAll = si->bind4.empty() && si->bind6.empty();
		
		if (!si->bind4.empty() || listenAll) {
			prepareProtocol(si, false);
		}
			
		if (!si->bind6.empty() || listenAll) {
			prepareProtocol(si, true);
		}
	}

	core.getClientManager().prepareSupports(hasV4Address && hasV6Address);

	io.run();

	io.reset();

	return 0;
}

void SocketManager::closeFactories() {
	for(auto i = factories.begin(), iend = factories.end(); i != iend; ++i) {
		(*i)->close();
	}
	factories.clear();
}

void SocketManager::addJob(const Callback& callback) throw() {
	io.post(callback);
}

void SocketManager::addJob(const long msec, const Callback& callback) {
	addJob(boost::posix_time::milliseconds(msec), callback);
}

void SocketManager::addJob(const std::string& time, const Callback& callback) {
	addJob(boost::posix_time::duration_from_string(time), callback);
}

SocketManager::Callback SocketManager::addTimedJob(const long msec, const Callback& callback) {
	return addTimedJob(boost::posix_time::milliseconds(msec), callback);
}

SocketManager::Callback SocketManager::addTimedJob(const std::string& time, const Callback& callback) {
	return addTimedJob(boost::posix_time::duration_from_string(time), callback);
}

void SocketManager::addJob(const deadline_timer::duration_type& duration, const Callback& callback) {
	setTimer(make_shared<timer_ptr::element_type>(io, duration), deadline_timer::duration_type(), new Callback(callback));
}

SocketManager::Callback SocketManager::addTimedJob(const deadline_timer::duration_type& duration, const Callback& callback) {
	timer_ptr timer = make_shared<timer_ptr::element_type>(io, duration);
	Callback* pCallback = new Callback(callback); // create a separate callback on the heap to avoid shutdown crashes
	setTimer(timer, duration, pCallback);
	return std::bind(&SocketManager::cancelTimer, this, timer, pCallback);
}

void SocketManager::setTimer(timer_ptr timer, const deadline_timer::duration_type& duration, Callback* callback) {
	timer->async_wait(std::bind(&SocketManager::handleWait, this, timer, duration, std::placeholders::_1, callback));
}

void SocketManager::handleWait(timer_ptr timer, const deadline_timer::duration_type& duration, const error_code& error, Callback* callback) {
	bool run_on = duration.ticks();

	if(!error) {
		if(run_on) {
			// re-schedule the timer
			timer->expires_at(timer->expires_at() + duration);
			setTimer(timer, duration, callback);
		}

		addJob(*callback);
	}

	if(!run_on) {
		// this timer was only running once, so it has no cancel function
		delete callback;
	}
}

void SocketManager::cancelTimer(timer_ptr timer, Callback* callback) {
	if(timer.get()) {
		error_code ec;
		timer->cancel(ec);
	}

	delete callback;
}

void SocketManager::shutdown() {
	closeFactories();

	work.reset();
	io.stop();
}

void SocketManager::onLoad(const SimpleXML& xml) throw() {
	servers.clear();
}

}
