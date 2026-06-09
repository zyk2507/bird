/*
 *	BIRD -- YANG-CBOR / CORECONF api -- CLI model
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _YANG_MODEL_CLI_H_
#define _YANG_MODEL_CLI_H_

#include "yang/yang.h"

#define YANG_SID_CLI_SHOW_MEMORY		60001
#define YANG_SID_CLI_SHOW_MEMORY_OUTPUT		60003

#define YANG_SID_CLI_SHOW_STATUS		60025
#define YANG_SID_CLI_SHOW_STATUS_OUTPUT		60027

#define YANG_SID_CLI_SHOW_SYMBOLS		60036
#define YANG_SID_CLI_SHOW_SYMBOLS_OUTPUT	60038

#define YANG_SID_CLI_SHOW_PROTOCOLS		60043
#define YANG_SID_CLI_SHOW_PROTOCOLS_OUTPUT	60045

bool yang_model_cli_rpc_call_show_memory(struct yang_session *se);
bool yang_model_cli_rpc_call_show_status(struct yang_session *se);
bool yang_model_cli_rpc_call_show_symbols(struct yang_session *se);
bool yang_model_cli_rpc_call_show_protocols(struct yang_session *se);

#endif /* _YANG_MODEL_CLI_H_ */
