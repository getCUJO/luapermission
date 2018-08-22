/*
 * Copyright (c) 2018 - 2019, CUJO LLC.
 * 
 * Licensed under the MIT license:
 * 
 *     http://www.opensource.org/licenses/mit-license.php
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <lua.h>
#include <lauxlib.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define pushres(L, R)   luaL_fileresult(L, R, NULL)
#define DEFAULT_BUFSIZE 16384

static int
pusherr(lua_State *L, const char *msg)
{
	lua_pushnil(L);
	lua_pushstring(L, msg);
	return 2;
}

static int
getuserid(const char *name, uid_t *uid)
{
	size_t bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = DEFAULT_BUFSIZE;

	char *buf = malloc(bufsize);
	if (buf == NULL)
		return 0;

	struct passwd pwd;
	struct passwd *result;
	errno = getpwnam_r(name, &pwd, buf, bufsize, &result);
	*uid = pwd.pw_uid;
	free(buf);
	return result != NULL;
}

static int
getgroupid(const char *name, gid_t *gid)
{
	size_t bufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
	if (bufsize == -1)
		bufsize = DEFAULT_BUFSIZE;

	char *buf = malloc(bufsize);
	if (buf == NULL)
		return 0;

	struct group grp;
	struct group *result;
	errno = getgrnam_r(name, &grp, buf, bufsize, &result);
	*gid = grp.gr_gid;
	free(buf);
	return result != NULL;
}

static int
lsetuser(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	uid_t uid;
	if (!getuserid(name, &uid)) {
		if (errno == 0) return pusherr(L, "unknown user");
		return pushres(L, 0);
	}
	return pushres(L, setuid(uid) == 0);
}

static int
lsetgroup(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	gid_t gid;
	if (!getgroupid(name, &gid)) {
		if (errno == 0) return pusherr(L, "unknown group");
		return pushres(L, 0);
	}
	return pushres(L, setgid(gid) == 0);
}

static int
lkeepcaps(lua_State *L)
{
	return pushres(L, prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0);
}

static int
checkcapflag(lua_State *L, int arg)
{
	static const struct { int value; const char *name; } capabilities[] = {
		{ CAP_CHOWN, "chown" },
		{ CAP_DAC_OVERRIDE, "dac_override" },
		{ CAP_DAC_READ_SEARCH, "dac_read_search" },
		{ CAP_FOWNER, "fowner" },
		{ CAP_FSETID, "fsetid" },
		{ CAP_IPC_LOCK, "ipc_lock" },
		{ CAP_IPC_OWNER, "ipc_owner" },
		{ CAP_KILL, "kill" },
		{ CAP_LINUX_IMMUTABLE, "linux_immutable" },
		{ CAP_NET_ADMIN, "net_admin" },
		{ CAP_NET_BIND_SERVICE, "net_bind_service" },
		{ CAP_NET_BROADCAST, "net_broadcast" },
		{ CAP_NET_RAW, "net_raw" },
		{ CAP_SETGID, "setgid" },
		{ CAP_SETPCAP, "setpcap" },
		{ CAP_SETUID, "setuid" },
		{ CAP_SYS_ADMIN, "sys_admin" },
		{ CAP_SYS_BOOT, "sys_boot" },
		{ CAP_SYS_CHROOT, "sys_chroot" },
		{ CAP_SYS_MODULE, "sys_module" },
		{ CAP_SYS_NICE, "sys_nice" },
		{ CAP_SYS_PACCT, "sys_pacct" },
		{ CAP_SYS_PTRACE, "sys_ptrace" },
		{ CAP_SYS_RAWIO, "sys_rawio" },
		{ CAP_SYS_RESOURCE, "sys_resource" },
		{ CAP_SYS_TIME, "sys_time" },
		{ CAP_SYS_TTY_CONFIG, "sys_tty_config" },
		{ CAP_WAKE_ALARM, "wake_alarm" },
		{ CAP_LEASE, "lease" }, /* since Linux 2.4 */
		{ CAP_MKNOD, "mknod" }, /* since Linux 2.4 */
		{ CAP_AUDIT_CONTROL, "audit_control" }, /* since Linux 2.6.11 */
		{ CAP_AUDIT_WRITE, "audit_write" }, /* since Linux 2.6.11 */
		{ CAP_SETFCAP, "setfcap" }, /* since Linux 2.6.24 */
		{ CAP_MAC_ADMIN, "mac_admin" }, /* since Linux 2.6.25 */
		{ CAP_MAC_OVERRIDE, "mac_override" }, /* since Linux 2.6.25 */
		{ CAP_SYSLOG, "syslog" }, /* since Linux 2.6.37 */
#ifdef CAP_BLOCK_SUSPEND
		{ CAP_BLOCK_SUSPEND, "block_suspend" }, /* since Linux 3.5 */
#endif
#ifdef CAP_AUDIT_READ
		{ CAP_AUDIT_READ, "audit_read" }, /* since Linux 3.16 */
#endif
		{ 0, NULL }
	};
	const char *name = luaL_checkstring(L, arg);
	for (int i = 0; capabilities[i].name; i++)
		if (strcmp(capabilities[i].name, name) == 0)
			return capabilities[i].value;
	return luaL_argerror(L, arg, lua_pushfstring(L, "invalid flag '%s'",
	                                             name));
}

static int
lsetupcaps(lua_State *L)
{
	int ncap = lua_gettop(L);
	for (int i = 1; i <= ncap; i++) {
		lua_pushinteger(L, checkcapflag(L, i));
		lua_replace(L, i);
	}

	cap_t caps = cap_init();
	if (!caps) return pushres(L, 0);

	cap_value_t *caplist = malloc(ncap * sizeof(cap_value_t));
	for (int i = 1; i <= ncap; i++)
		caplist[i - 1] = lua_tointeger(L, i);
	cap_set_flag(caps, CAP_PERMITTED, ncap, caplist, CAP_SET);
	cap_set_flag(caps, CAP_EFFECTIVE, ncap, caplist, CAP_SET);
	cap_set_flag(caps, CAP_INHERITABLE, ncap, caplist, CAP_SET);

	int res = cap_set_proc(caps);
	cap_free(caps);
	free(caplist);
	return pushres(L, res != -1);
}

static int
lsetambientcap(lua_State *L)
{
	int cap = checkcapflag(L, 1);
	int res = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0);
	return pushres(L, res >= 0);
}

static const luaL_Reg lib[] =
{
	{ "setuser", lsetuser },
	{ "setgroup", lsetgroup },
	{ "keepcaps", lkeepcaps },
	{ "setupcaps", lsetupcaps },
	{ "setambientcap", lsetambientcap },
	{ NULL, NULL }
};

LUALIB_API int
luaopen_cujo_permission(lua_State *L)
{
	luaL_newlib(L, lib);
	return 1;
}
