/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>

#define command_print(expr ...)

#define LOG_INFO(expr ...) \
	printf(expr)

#define LOG_WARNING(expr ...) \
	printf(expr)

#define LOG_ERROR(expr ...) \
	printf(expr)

#define LOG_USER(expr ...) \
	printf(expr)

#define LOG_USER_N(expr ...) \
	printf(expr)

#define LOG_OUTPUT(expr ...) \
	printf(expr)

/* general failures
 * error codes < 100
 */
#define ERROR_OK						(0)
#define ERROR_NO_CONFIG_FILE			(-2)
#define ERROR_BUF_TOO_SMALL				(-3)
/* see "Error:" log entry for meaningful message to the user. The caller should
 * make no assumptions about what went wrong and try to handle the problem.
 */
#define ERROR_FAIL						(-4)
#define ERROR_WAIT						(-5)
/* ERROR_TIMEOUT is already taken by winerror.h. */
#define ERROR_TIMEOUT_REACHED			(-6)
#define ERROR_NOT_IMPLEMENTED			(-7)

#define ERROR_COMMAND_CLOSE_CONNECTION		(-600)
#define ERROR_COMMAND_SYNTAX_ERROR			(-601)
#define ERROR_COMMAND_NOTFOUND				(-602)
#define ERROR_COMMAND_ARGUMENT_INVALID		(-603)
#define ERROR_COMMAND_ARGUMENT_OVERFLOW		(-604)
#define ERROR_COMMAND_ARGUMENT_UNDERFLOW	(-605)

#endif
