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

#ifndef ADCHPP_CID_H
#define ADCHPP_CID_H

#include "Util.h"
#include "Encoder.h"

namespace adchpp {
	
class CID {
public:
	enum { SIZE = 192 / 8 };
	enum { BASE32_SIZE = 39 };

	CID() noexcept { memset(cid, 0, sizeof(cid)); }
	explicit CID(const uint8_t* data) noexcept { memcpy(cid, data, sizeof(cid)); }
	explicit CID(const std::string& base32) noexcept { Encoder::fromBase32(base32.c_str(), cid, sizeof(cid)); }

	CID(const CID& rhs) noexcept { memcpy(cid, rhs.cid, sizeof(cid)); }
	CID& operator=(const CID& rhs) noexcept { memcpy(cid, rhs.cid, sizeof(cid)); return *this; }

	bool operator==(const CID& rhs) const noexcept { return memcmp(cid, rhs.cid, sizeof(cid)) == 0; }
	bool operator<(const CID& rhs) const noexcept { return memcmp(cid, rhs.cid, sizeof(cid)) < 0; }

	std::string toBase32() const noexcept { return Encoder::toBase32(cid, sizeof(cid)); }
	std::string& toBase32(std::string& tmp) const noexcept { return Encoder::toBase32(cid, sizeof(cid), tmp); }

	size_t toHash() const noexcept { static_assert(sizeof(cid) >= sizeof(cidHash), "cid too small, cidHash invalid"); return cidHash; }
	const uint8_t* data() const noexcept { return cid; }

	bool isZero() const noexcept { return std::all_of(cid, cid + SIZE, [](uint8_t c) { return c == 0; }); }

	static CID generate() noexcept {
		uint8_t data[CID::SIZE];
		for(size_t i = 0; i < sizeof(data); ++i) {
			data[i] = (uint8_t)Util::rand();
		}
		return CID(data);
	}

private:
	union {
		uint8_t cid[SIZE];
		size_t cidHash;
	};
};

}

namespace std {
template<>
struct hash<adchpp::CID> {
	size_t operator()(const adchpp::CID& cid) const {
		return cid.toHash();
	}
};
}

#endif
