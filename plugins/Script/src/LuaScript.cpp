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

#include "stdinc.h"
#include "LuaScript.h"

#include <adchpp/LogManager.h>
#include <adchpp/Util.h>

#ifdef _WIN32
#include <direct.h>
#else
#ifndef MAX_PATH
#define MAX_PATH PATH_MAX
#endif

#endif

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

}

const string LuaScript::className = "LuaScript";

LuaScript::LuaScript(Engine* engine) : Script(engine), l(0) {
	l = lua_open();
	luaL_openlibs(l);
	wrapper.wrap(l);
}

LuaScript::~LuaScript() {
	if(l)
		lua_close(l);	
}

void LuaScript::loadFile(const string& path, const string& filename_) {
	filename = filename_;
	char old_dir[MAX_PATH];
	getcwd(old_dir, MAX_PATH);
	
	chdir(path.c_str());

	int error = luaL_loadfile(l, filename.c_str()) || lua_pcall(l, 0, 0, 0);	
	
	if(error) {
		LOGDT(className, string("Error loading file: ") + lua_tostring(l, -1));
	} else {
		LOGDT(className, "Loaded " + filename);
	}
	chdir(old_dir);
}

void LuaScript::getStats(string& str) const {
	str += filename + "\n";
	str += "\tUsed Memory: " + Util::toString(lua_gc(l, LUA_GCCOUNT, 0)) + " KiB\n";
}