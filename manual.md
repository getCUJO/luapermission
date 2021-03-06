Index
=====

- [`permission.keepcaps`](#permissionkeepcaps)
- [`permission.setgroup`](#permissionsetgroupgroup)
- [`permission.setuser`](#permissionsetuseruser)
- [`permission.setupcaps`](#permissionsetupcapscap-cap-)
- [`permission.setambientcap`](#permissionsetambientcapcap)

Contents
========

CUJO Permissions
----------------

This library provides functions to control the process permissions on the system.
Unless otherwise noted, in case of errors, all functions described below return `nil`, followed by an error message and an error number.

### `permission.keepcaps()`

Retains the ability to inherit the current capabilities after changing users.
Must be called before changing users to allow using [`permission.setupcaps`](#permissionsetupcapscap-cap-) afterwards.

### `permission.setgroup(group)`

Changes the group of the current process to the group with name `group`.

### `permission.setuser(user)`

Changes the user of the current process to the user with name `user`.

### `permission.setupcaps(cap1, cap2, ...)`

Sets the current process' effective, inheritable and permitted capabilities to the ones provided.
Each cap is a string representing a capability. This is the same name as the symbol in the kernel, but lowercase and without the `CAP_` prefix. I.e. `CAP_NET_ADMIN` becomes `"net_admin"`.
See the [list of supported capabilities](#supported-caps) bellow.

### `permission.setambientcap(cap)`

Adds a capability to the current process' ambient set. This allows other processes we start to inherent these capabilities.
Unlike [`permission.setupcaps`](#permissionsetupcapscap-cap-), this function takes a single capability string and adds it to the current set.
See the [list of supported capabilities](#supported-caps) bellow.

### Supported caps

- "chown"
- "dac\_override"
- "dac\_read\_search"
- "fowner"
- "fsetid"
- "ipc\_lock"
- "ipc\_owner"
- "kill"
- "linux\_immutable"
- "net\_admin"
- "net\_bind\_service"
- "net\_broadcast"
- "net\_raw"
- "setgid"
- "setpcap"
- "setuid"
- "sys\_admin"
- "sys\_boot"
- "sys\_chroot"
- "sys\_module"
- "sys\_nice"
- "sys\_pacct"
- "sys\_ptrace"
- "sys\_rawio"
- "sys\_resource"
- "sys\_time"
- "sys\_tty\_config"
- "wake\_alarm"
- "lease"
- "mknod"
- "audit\_control"
- "audit\_write"
- "setfcap"
- "mac\_admin"
- "mac\_override"
- "syslog"
- "block\_suspend"
- "audit\_read"
