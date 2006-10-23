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

#include "adchpp.h"

#include "SocketManager.h"

#include "LogManager.h"
#include "TimerManager.h"
#include "ClientManager.h"
#include "SettingsManager.h"
#include "Semaphores.h"
#include "ManagedSocket.h"
#include "Thread.h"

#include <boost/bind.hpp>

#ifdef _WIN32
#include <MSWSock.h>
#endif

#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#endif

namespace adchpp {

#ifdef _WIN32

#define ACCEPT_BUF_SIZE ((sizeof(SOCKADDR_IN)+16)*2)

struct MSOverlapped : OVERLAPPED {
	enum Types {
		ACCEPT,
		READ_DONE,
		WRITE_DONE,
		WRITE_WAITING,
		WRITE_ALL,
		DISCONNECT,
		SHUTDOWN
	} type;
	ManagedSocketPtr ms;
	
	MSOverlapped() { memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED)); }
	MSOverlapped(Types type_) : type(type_) { memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED)); }
	MSOverlapped(Types type_, const ManagedSocketPtr& ms_) : type(type_), ms(ms_) { memset(static_cast<OVERLAPPED*>(this), 0, sizeof(OVERLAPPED)); }
};

struct ClearOverlapped {
	void operator()(MSOverlapped& overlapped) {
		overlapped.ms = 0;
	}
};

class CompletionPort {
public:
	CompletionPort() : handle(INVALID_HANDLE_VALUE) { 
	}
	
	~CompletionPort() { 
		if(handle != INVALID_HANDLE_VALUE) 
			::CloseHandle(handle); 
	}
	
	bool create() {
		handle = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, 0);
		return handle != NULL;
	}

	bool associate(socket_t socket) {
		return ::CreateIoCompletionPort(reinterpret_cast<HANDLE>(socket), handle, 0, 0) != FALSE;
	}
	
	bool post(MSOverlapped* overlapped) {
		return ::PostQueuedCompletionStatus(handle, 0, 0, overlapped) != FALSE;
	}
	
	bool get(DWORD* bytes, MSOverlapped** overlapped) {
		DWORD x = 0;
		return ::GetQueuedCompletionStatus(handle, bytes, &x, reinterpret_cast<OVERLAPPED**>(overlapped), 1000);
	}
	
	operator bool() { return handle != INVALID_HANDLE_VALUE; }
private:
	HANDLE handle;
};

class Writer : public Thread {
public:
	static const size_t PREPARED_SOCKETS = 32;
	
	Writer() : stop(false) {
	}
	
	void addWriter(ManagedSocketPtr ms) {
		if(stop)
			return;
		if(ms->writeBuf) {
			// Already writing...
			return;
		}
		MSOverlapped* overlapped = pool.get();
		*overlapped = MSOverlapped(MSOverlapped::WRITE_WAITING, ms);
		
		if(!port.post(overlapped)) {
			LOGDT(SocketManager::className, "Fatal error while posting write to completion port: " + Util::translateError(::GetLastError()));
		}			
	}
	
	void addAllWriters() {
		if(stop)
			return;
			
		MSOverlapped* overlapped = pool.get();
		*overlapped = MSOverlapped(MSOverlapped::WRITE_ALL);
		
		if(!port.post(overlapped)) {
			LOGDT(SocketManager::className, "Fatal error while posting writeAll to completion port: " + Util::translateError(::GetLastError()));
		}			
	}
	
	void addDisconnect(ManagedSocketPtr ms) {
		if(stop)
			return;
			
		MSOverlapped* overlapped = pool.get();
		*overlapped = MSOverlapped(MSOverlapped::DISCONNECT, ms);
		
		if(!port.post(overlapped)) {
			LOGDT(SocketManager::className, "Fatal error while posting disconnect to completion port: " + Util::translateError(::GetLastError()));
		}			
	}			
	
	void shutdown() {
		stop = true;
		
		MSOverlapped* overlapped = pool.get();
		*overlapped = MSOverlapped(MSOverlapped::SHUTDOWN);
		
		if(!port.post(overlapped)) {
			LOGDT(SocketManager::className, "Fatal error while posting shutdown to completion port: " + Util::translateError(::GetLastError()));
		}
		join();
	}
	
private:
	bool init() {
		if(!port.create()) {
			LOGDT(SocketManager::className, "Unable to create IO Completion port: " + Util::translateError(::GetLastError()));
			return false;
		}

		try {
			srv.listen(static_cast<short>(SETTING(SERVER_PORT)));
		} catch(const SocketException& e) {
			LOGDT(SocketManager::className, "Unable to create server socket: " + e.getError());
			return false;
		} 
		
		if(!port.associate(srv.getSocket())) {
			LOGDT(SocketManager::className, "Unable to associate IO Completion port: " + Util::translateError(::GetLastError()));
			return false;
		}
	
		return true;
	}
	
	virtual int run() {
		LOGDT(SocketManager::className, "Writer starting");
		if(!init()) {
			return 0;
		}
		
		prepareAccept();
		
		DWORD bytes = 0;
		MSOverlapped* overlapped = 0;
		
		while(!stop || !accepting.empty() || !active.empty()) {
			bool ret = port.get(&bytes, &overlapped);
			//dcdebug("Event: %x, %x, %x, %x, %x, %x\n", (unsigned int)ret, (unsigned int)bytes, (unsigned int)ms, (unsigned int)overlapped, (unsigned int)overlapped->ms, (unsigned int)overlapped->type);
			
			if(!ret) {
				if(overlapped == 0) {
					int error = ::GetLastError();
					if(error == WAIT_TIMEOUT) {
						checkDisconnects();
						continue;
					}
					LOGDT(SocketManager::className, "Fatal error while getting status from completion port: " + Util::translateError(error));
					return error;
				} else if(overlapped->type == MSOverlapped::ACCEPT) {
					dcdebug("Error accepting: %s\n", Util::translateError(::GetLastError()).c_str());
					failAccept(overlapped->ms);
				} else if(overlapped->type == MSOverlapped::READ_DONE) {
					dcdebug("Error reading: %s\n", Util::translateError(::GetLastError()).c_str());
					failRead(overlapped->ms);
				} else if(overlapped->type == MSOverlapped::WRITE_DONE) {
					dcdebug("Error writing: %s\n", Util::translateError(::GetLastError()).c_str());
					failWrite(overlapped->ms);
				} else {
					dcdebug("Unknown error %d when waiting\n", overlapped->type);
				}
				pool.put(overlapped);
				continue;
			}	
			
			switch(overlapped->type) {
				case MSOverlapped::ACCEPT: {
					checkDisconnects();
					handleAccept(overlapped->ms);
					break;
				}
				case MSOverlapped::READ_DONE: {
					handleReadDone(overlapped->ms);
					break;
				}
				case MSOverlapped::WRITE_DONE: {
					handleWriteDone(overlapped->ms, bytes);
					break;
				}
				case MSOverlapped::WRITE_WAITING: {
					prepareWrite(overlapped->ms);
					break;
				}
				case MSOverlapped::WRITE_ALL: {
					handleWriteAll();
					break;
				}
				case MSOverlapped::DISCONNECT: {
					handleDisconnect(overlapped->ms);
					break;
				}
				case MSOverlapped::SHUTDOWN: {
					handleShutdown();
					break;
				} 
			}
			pool.put(overlapped);
		}
		LOGDT(SocketManager::className, "Writer shutting down");
		return 0;
	}

	void prepareAccept() throw() {
		if(stop)
			return;
		
		if(accepting.size() > PREPARED_SOCKETS / 2) {
			return;
		}
		
		while(accepting.size() < PREPARED_SOCKETS) {
			ManagedSocketPtr ms(new ManagedSocket());
			try {
				ms->create();
			} catch (const SocketException& e) {
				LOGDT(SocketManager::className, "Unable to create socket: " + e.getError());
				return;
			}
				
			if(!port.associate(ms->getSocket())) {
				LOGDT(SocketManager::className, "Unable to associate IO Completion port: " + Util::translateError(::GetLastError()));
				return;
			}

			DWORD x = 0;

			ms->writeBuf = Util::freeBuf;
			ms->writeBuf->resize(ACCEPT_BUF_SIZE);
			
			MSOverlapped* overlapped = pool.get();
			*overlapped = MSOverlapped(MSOverlapped::ACCEPT, ms);

			if(!::AcceptEx(srv.getSocket(), ms->getSocket(), &(*ms->writeBuf)[0], 0, ACCEPT_BUF_SIZE/2, ACCEPT_BUF_SIZE/2, &x, overlapped)) {
				if(::WSAGetLastError() != ERROR_IO_PENDING) {
					if(!stop) {
						LOGDT(SocketManager::className, "Failed accepting connection: " + Util::translateError(GetLastError()));
					}
					
					pool.put(overlapped);
					return;
				}
			}
			
			accepting.insert(ms);
		}
	}

	void handleAccept(const ManagedSocketPtr& ms) throw() {
		struct sockaddr_in *local, *remote;
		int sz1 = sizeof(local), sz2 = sizeof(remote);
		
		::GetAcceptExSockaddrs(&(*ms->writeBuf)[0], 0, ACCEPT_BUF_SIZE/2, ACCEPT_BUF_SIZE/2, reinterpret_cast<sockaddr**>(&local), &sz1, reinterpret_cast<sockaddr**>(&remote), &sz2);
		
		ms->setIp(inet_ntoa(remote->sin_addr));
	
		Util::freeBuf = ms->writeBuf;
		ms->writeBuf = 0;
	
		active.insert(ms);
		accepting.erase(ms);

		ClientManager::getInstance()->incomingConnection(ms);

		ms->completeAccept();
		
		prepareRead(ms);
		// Prepare a new socket to replace this one...
		prepareAccept();	
	}
	
	void failAccept(ManagedSocketPtr& ms) throw() {
		accepting.erase(ms);
		
		prepareAccept();
	}
	
	void prepareRead(const ManagedSocketPtr& ms) throw() {
		if(stop)
			return;
			
		DWORD x = 0;
		DWORD flags = 0;
		WSABUF wsabuf = { 0, 0 };
		
		MSOverlapped* overlapped = pool.get();
		*overlapped = MSOverlapped(MSOverlapped::READ_DONE, ms);
		
		if(::WSARecv(ms->getSocket(), &wsabuf, 1, &x, &flags, reinterpret_cast<LPWSAOVERLAPPED>(overlapped), 0) != 0) {
			int error = ::WSAGetLastError();
			if(error != WSA_IO_PENDING) {
				dcdebug("Error preparing read: %s\n", Util::translateError(error).c_str());
				failRead(ms);
			}
		}
	}
	
	void handleReadDone(const ManagedSocketPtr& ms) throw() {
		ByteVector* readBuf = Util::freeBuf;
		
		if(readBuf->size() < (size_t)SETTING(BUFFER_SIZE))
			readBuf->resize(SETTING(BUFFER_SIZE));
		
		WSABUF wsa = { (u_long)readBuf->size(), (char*)&(*readBuf)[0] };
		
		DWORD bytes = 0;
		DWORD flags = 0;
		
		if(::WSARecv(ms->getSocket(), &wsa, 1, &bytes, &flags, 0, 0) == SOCKET_ERROR) {
			if(::WSAGetLastError() != WSAEWOULDBLOCK) {
				// Socket failed...
				Util::freeBuf = readBuf;
				failRead(ms);
				return;
			}
			
			Util::freeBuf = readBuf;
			prepareRead(ms);
			return;
		}
		
		if(bytes == 0) {
			Util::freeBuf = readBuf;
			failRead(ms);
			return;
		}
		
		readBuf->resize(bytes);
		ms->completeRead(readBuf);
		
		prepareRead(ms);
	}
	
	void failRead(const ManagedSocketPtr& ms) throw() {
		if(active.find(ms) == active.end()) {
			return;
		}
		active.erase(ms);
		disconnecting.erase(ms);
		
		ms->close();
		ms->failSocket();
	}
	
	void prepareWrite(const ManagedSocketPtr& ms) throw() {
		if(stop || ms->writeBuf) {
			return;
		}
		
		ms->writeBuf = ms->prepareWrite();
		
		if(!ms->writeBuf) {
			if(ms->disc) {
				ms->close();
			}
			return;
		}
		
		ms->wsabuf.len = ms->writeBuf->size();
		ms->wsabuf.buf = reinterpret_cast<char*>(&(*ms->writeBuf)[0]);

		MSOverlapped* overlapped = pool.get();
		*overlapped = MSOverlapped(MSOverlapped::WRITE_DONE, ms);
		
		DWORD x = 0;
		if(::WSASend(ms->getSocket(), &ms->wsabuf, 1, &x, 0, reinterpret_cast<LPWSAOVERLAPPED>(overlapped), 0) != 0) {
			if(::WSAGetLastError() != WSA_IO_PENDING) {
				failWrite(ms);
				pool.put(overlapped);
			}
		}
		return;
	}
	
	void handleWriteDone(const ManagedSocketPtr& ms, DWORD bytes) throw() {
		ByteVector* buf = ms->writeBuf;
		ms->writeBuf = 0;
		
		if(!buf) {
			dcdebug("No buffer in handleWriteDone??\n");
			return;
		}
		if(ms->completeWrite(buf, bytes)) {
			prepareWrite(ms);
		}
	}
	
	void failWrite(const ManagedSocketPtr& ms) throw() {
		Util::freeBuf = ms->writeBuf;
		ms->writeBuf = 0;
		
		ms->close();
	}
	
	void handleWriteAll() throw() {
		for(SocketSet::iterator i = active.begin(); i != active.end(); ++i) {
			prepareWrite(*i);
		}
	}
	
	void handleDisconnect(const ManagedSocketPtr& ms) throw() {
		if(active.find(ms) == active.end()) {
			return;
		}
		
		prepareWrite(ms);
		disconnecting.insert(ms);
	}
	
	void checkDisconnects() throw() {
		uint32_t now = GET_TICK();
		for(SocketSet::iterator i = disconnecting.begin(); i != disconnecting.end(); ++i) {
			const ManagedSocketPtr& ms = *i;
			if(ms->disc + (uint32_t)SETTING(DISCONNECT_TIMEOUT) < now) {
				ms->close();
			}
		}
	}
	
	void handleShutdown() throw() {
		for(SocketSet::iterator i = accepting.begin(); i != accepting.end(); ++i) {
			(*i)->close();
		}
		for(SocketSet::iterator i = active.begin(); i != active.end(); ++i) {
			(*i)->close();
		}
	}
	
	CompletionPort port;
	Socket srv;
	
	bool stop;
	
	Pool<MSOverlapped, ClearOverlapped> pool;
	
	typedef HASH_SET<ManagedSocketPtr, PointerHash<ManagedSocket> > SocketSet;
	/** Sockets that have a pending read */
	SocketSet active;
	/** Sockets that have a pending accept */
	SocketSet accepting;
	/** Sockets that are being written to but should be disconnected if timeout it reached */
	SocketSet disconnecting;
};

#elif defined(HAVE_SYS_EPOLL_H)

struct EPoll {
	EPoll() : poll_fd(-1) { 
	}
	
	~EPoll() { 
		if(poll_fd != -1) {
			close(poll_fd);
		}
	}
	
	bool init() {
		poll_fd = epoll_create(1024);
		if(poll_fd == -1)
			return false;
		
		return true;
	}
	
	bool associate(const ManagedSocketPtr& ms) {
		epoll_event ev = { 0, 0 };
		ev.data.ptr = reinterpret_cast<void*>(ms);
		ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
		return epoll_ctl(poll_fd, EPOLL_CTL_ADD, ms->getSocket(), &ev) == 0;
	}
	
	bool associate(int fd) {
		epoll_event ev = { 0, 0 };
		ev.data.fd = fd;
		ev.events = EPOLLIN;
		return epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd, &ev) == 0;
	}
	
	bool get(vector<epoll_event>& events) {
		events.resize(1024);
		int n = epoll_wait(poll_fd, &events[0], events.size(), -1);
		if(n == -1) {
			return false;
		}
		events.resize(n);
		return true;
	}
	
	int poll_fd;
};

struct Event {
	enum Type {
		WRITE,
		WRITE_ALL,
		DISCONNECT,
		SHUTDOWN
	} event;
	const ManagedSocketPtr& ms;
	
	Event(Type event_, const ManagedSocketPtr& ms_) : event(event_), ms(ms_) { }
	Event() : event(WRITE), ms(0) { }
};

class Writer : public Thread {
public:
	static const size_t INITIAL_SOCKETS = 32;
	
	Writer() : stop(false) {
	}
	
	void addWriter(const ManagedSocketPtr& ms) {
		if(stop)
			return;
		
		Event ev(Event::WRITE, ms);
		::write(event[0], &ev, sizeof(ev));
	}
	
	void addAllWriters() {
		if(stop)
			return;
		Event ev(Event::WRITE_ALL, 0);
		::write(event[0], &ev, sizeof(ev));
	}
	
	void addDisconnect(const ManagedSocketPtr& ms) {
		if(stop)
			return;
			
		Event ev(Event::DISCONNECT, ms);
		::write(event[0], &ev, sizeof(ev));
	}			
	
	void shutdown() {
		stop = true;

		Event ev(Event::SHUTDOWN, 0);
		::write(event[0], &ev, sizeof(ev));

		join();
	}
	
private:
	bool init() {
		poller.init();
		
		try {
			srv.listen(SETTING(SERVER_PORT));
			srv.setBlocking(false);
		} catch(const SocketException& e) {
			LOGDT(SocketManager::className, "Unable to create server socket: " + e.getError());
			return false;
		} 
		
		if(!poller.associate(srv.getSocket())) {
			LOGDT(SocketManager::className, "Unable to set epoll: " + Util::translateError(errno));
			return false;
		}
		
		if(socketpair(AF_UNIX, SOCK_STREAM, 0, event) == -1) {
			LOGDT(SocketManager::className, "Unable to create event socketpair: " + Util::translateError(errno));
			return false;
		}
		if(!poller.associate(event[1])) {
			LOGDT(SocketManager::className, "Unable to associate event: " + Util::translateError(errno));
			return false;
		}
		return true;
	}
	
	virtual int run() {
		LOGDT(SocketManager::className, "Writer starting");
		if(!init()) {
			return 2;
		}
		
		while(!stop || !active.empty()) {
			checkDisconnects();
			std::vector<epoll_event> events;
			if(!poller.get(events)) {
				LOGDT(SocketManager::className, "Poller failed: " + Util::translateError(errno));
			}
			for(std::vector<epoll_event>::iterator i = events.begin(); i != events.end(); ++i) {
				epoll_event& ev = *i;
				if(ev.data.fd == srv.getSocket()) {
					printf("accepting\n");
					accept();
				} else if(ev.data.fd == event[1]) {
					handleEvents();
				} else {
					const ManagedSocketPtr& ms = reinterpret_cast<const ManagedSocketPtr&>(ev.data.ptr);
					if(ev.events & EPOLLIN || ev.events & EPOLLERR) {
						read(ms);
					} else if(ev.events & EPOLLOUT) {
						write(ms);
					}
				}
			}
		}
		LOGDT(SocketManager::className, "Writer shutting down");
		return 0;
	}
	
	void handleEvents() {
		Event ev[16];
		while(true) {
			int bytes = ::recv(event[1], ev, sizeof(ev), MSG_DONTWAIT);
			if(bytes == -1) {
				int err = errno;
				if(err == EAGAIN) {
					return;
				}
			}
			for(size_t i = 0; i*sizeof(ev[0]) < static_cast<size_t>(bytes); ++i) {
				switch(ev[i].event) {
					case Event::WRITE: {
						write(ev[i].ms);
					} break;
					case Event::WRITE_ALL: {
						writeAll();
					} break;
					case Event::DISCONNECT: {
						disconnect(ev[i].ms);
					} break;
					case Event::SHUTDOWN: {
						handleShutdown();
					} break;
				}
			}
		}	
	}
	
	void accept() throw() {
		ManagedSocketPtr ms(new ManagedSocket());
		try {
			ms->setIp(ms->sock.accept(srv));
					
			if(!poller.associate(ms)) {
				LOGDT(SocketManager::className, "Unable to associate EPoll: " + Util::translateError(errno));
				return;
			}
	
			active.insert(ms);

			ClientManager::getInstance()->incomingConnection(ms);
			
			ms->completeAccept(); 
		
			read(ms);
		} catch (const SocketException& e) {
			LOGDT(SocketManager::className, "Unable to create socket: " + e.getError());
			return;
		}
	}
	
	void read(const ManagedSocketPtr& ms) throw() {
		if(stop)
			return;
		while(true) {
			// Read until we can read no more
			ByteVector* readBuf = Util::freeBuf;
			if(readBuf->size() < (size_t)SETTING(BUFFER_SIZE))
				readBuf->resize(SETTING(BUFFER_SIZE));
			ssize_t bytes;
			bytes = ::recv(ms->getSocket(), &(*readBuf)[0], readBuf->size(), MSG_DONTWAIT);
			if(bytes == -1) {
				Util::freeBuf = readBuf;
				
				int error = errno;
				if(error != EAGAIN) {
					failRead(ms);
				}
				return;
			} else if(bytes == 0) {
				Util::freeBuf = readBuf;
				failRead(ms);
				return;
			}
			readBuf->resize(bytes);
			ms->completeRead(readBuf);
		}
	}
	
	void failRead(const ManagedSocketPtr& ms) throw() {
		if(active.find(ms) == active.end()) {
			return;
		}
		active.erase(ms);
		
		ms->failSocket();
		
		ms->close();
	}
	
	void write(const ManagedSocketPtr& ms) throw() {
		if(stop) {
			return;
		}
		
		while(true) {
			ByteVector* writeBuf = ms->prepareWrite();
			
			if(!writeBuf) {
				if(ms->disc) {
					ms->shutdown();
				}
				return;
			}
			
			ssize_t bytes = ::send(ms->getSocket(), &(*writeBuf)[0], writeBuf->size(), MSG_DONTWAIT);
			if(bytes == -1) {
				Util::freeBuf = writeBuf;
				int error = errno;
				if(error == EAGAIN) {
					return;
				}
				failWrite(ms);
				return;
			}
			if(!ms->completeWrite(writeBuf, bytes)) {
				break;
			}
		}
	}
	
	void failWrite(const ManagedSocketPtr& ms) throw() {
		failRead(ms);
	}
	
	void writeAll() throw() {
		for(SocketSet::iterator i = active.begin(); i != active.end(); ++i) {
			write(*i);
		}
	}
	
	void disconnect(const ManagedSocketPtr& ms) throw() {
		failRead(ms);
		disconnecting.insert(ms);
	}
	
	void checkDisconnects() throw() {
		uint32_t now = GET_TICK();
		for(SocketSet::iterator i = disconnecting.begin(); i != disconnecting.end(); ++i) {
			const ManagedSocketPtr& ms = *i;
			if(ms->disc + (uint32_t)SETTING(DISCONNECT_TIMEOUT) < now) {
				failRead(ms);
			}
		}
	}
	
	void handleShutdown() throw() {
		SocketSet tmp(active);
		for(SocketSet::iterator i = tmp.begin(); i != tmp.end(); ++i) {
			failRead(*i);
		}
	}
	
	EPoll poller;
	Socket srv;
	
	bool stop;

	int event[2];
		
	typedef HASH_SET<ManagedSocketPtr, PointerHash<ManagedSocket> > SocketSet;
	/** Sockets that have a pending read */
	SocketSet active;
	/** Sockets that are being written to but should be disconnected if timeout it reached */
	SocketSet disconnecting;
};

#else
#error No socket implementation for your platform
#endif // _WIN32
	
SocketManager::SocketManager() : writer(new Writer()) { 
}

SocketManager::~SocketManager() {
}

SocketManager* SocketManager::instance = 0;
const string SocketManager::className = "SocketManager";

int SocketManager::run() {
	LOGDT(SocketManager::className, "Starting");
	writer->start();
	writer->setThreadPriority(Thread::HIGH);
	
	while(true) {
		processSem.wait();
		{
			FastMutex::Lock l(processCS);
			workQueue.swap(processQueue);
		}
		for(ProcessQueue::iterator i = workQueue.begin(); i != workQueue.end(); ++i) {
			if(!(*i)) {
				LOGDT(SocketManager::className, "Shutting down");
				return 0;
			}
			(*i)();
		}
		workQueue.clear();
	}
	LOGDT(SocketManager::className, "ERROR; should never end up here...");
	return 0;
}

void SocketManager::addWriter(const ManagedSocketPtr& ms) throw() {
	writer->addWriter(ms);
}

void SocketManager::addAllWriters() throw() {
	writer->addAllWriters();	
}

void SocketManager::addDisconnect(const ManagedSocketPtr& ms) throw() {
	writer->addDisconnect(ms);
}

void SocketManager::addJob(const Callback& callback) throw() { 
	FastMutex::Lock l(processCS);

	processQueue.push_back(callback);
	processSem.signal(); 
}

void SocketManager::shutdown() {
	writer->shutdown();

	addJob(Callback());
	join();
	
	writer.release();
}

}
