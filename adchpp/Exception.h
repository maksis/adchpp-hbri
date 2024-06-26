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

#ifndef ADCHPP_EXCEPTION_H
#define ADCHPP_EXCEPTION_H

#include "common.h"

namespace adchpp {
	
class ADCHPP_VISIBLE Exception : public std::exception
{
public:
	Exception() { }
	Exception(const std::string& aError) noexcept : error(aError) { dcdebug("Thrown: %s\n", error.c_str()); }
	virtual ~Exception() noexcept { }
	const std::string& getError() const noexcept { return error; }
	
	virtual const char* what() const noexcept { return error.c_str(); }
protected:
	std::string error;
};

#ifndef NDEBUG

#define STANDARD_EXCEPTION(name) class ADCHPP_VISIBLE name : public Exception { \
public:\
	name() noexcept : Exception(#name) { } \
	name(const std::string& aError) noexcept : Exception(#name ": " + aError) { } \
	virtual ~name() noexcept { } \
}

#else // NDEBUG

#define STANDARD_EXCEPTION(name) class ADCHPP_VISIBLE name : public Exception { \
public:\
	name() noexcept : Exception() { } \
	name(const std::string& aError) noexcept : Exception(aError) { } \
	virtual ~name() noexcept { } \
}
#endif

}

#endif // EXCEPTION_H
