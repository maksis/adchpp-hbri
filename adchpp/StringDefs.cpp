#include "stdinc.h"
#include "common.h"
#include "ResourceManager.h"
namespace adchpp {
	

string ResourceManager::strings[] = {
"B", 
"Your client's IP is incorrectly configured, and you will therefore be disconnected. Either you have to enter the correct one in the IP field in your client settings or try passive mode. Your current ip is: ", 
"CID taken", 
"Disk full?", 
"Please send your password", 
"You're flooding. Adios.", 
"GiB", 
"Hub is currently full", 
"You're connecting from an IP that's not allowed (banned) on this hub. If you feel this is wrong, you can always try contacting the owner of the hub.", 
"KiB", 
"MiB", 
"Your nick contains invalid characters. Adios.", 
"Your nick is already taken, please select another one", 
"Your nick is %d characters too long", 
"Not connected", 
"Permission denied", 
"You're permanently banned from this hub. Go away.", 
"You're permanently banned from this hub because: ", 
"Share size requirement not met, you need to share %s more.", 
"TiB", 
"You're banned from this hub (time left: %s).", 
"You're banned from this hub (time left: %s) because: ", 
"Unable to create thread", 
};
string ResourceManager::names[] = {
"B", 
"BadIp", 
"CidTaken", 
"DiskFull", 
"EnterPassword", 
"Flooding", 
"Gb", 
"HubFull", 
"IpUnallowed", 
"Kb", 
"Mb", 
"NickInvalid", 
"NickTaken", 
"NickTooLong", 
"NotConnected", 
"PermissionDenied", 
"PermBanned", 
"PermBannedReason", 
"ShareSizeNotMet", 
"Tb", 
"TempBanned", 
"TempBannedReason", 
"UnableToCreateThread", 
};
}