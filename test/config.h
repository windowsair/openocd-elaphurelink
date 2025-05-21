/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <sys/param.h>

#define __COMMAND_HANDLER(name, extra ...) \
	int name(void *cmd, ## extra)

#define COMMAND_HANDLER(name) \
	static __COMMAND_HANDLER(name)

#define CMD_ARGC 0
#define CMD_ARGV ((char **)(cmd))
#define CMD 0

#define COMMAND_REGISTRATION_DONE { .name = NULL }

enum command_mode {
	COMMAND_EXEC,
	COMMAND_CONFIG,
	COMMAND_ANY,
	COMMAND_UNKNOWN = -1, /* error condition */
};

struct command_registration {
	const char *name;
	void *handler;
	enum command_mode mode;
	const char *help;
	const char *usage;
};

#endif
