/***************************************************************************
 *   Copyright (C) 2019 by Daniel Anselmi								  *
 *   danselmi@gmx.ch													   *
 *																		 *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or	 *
 *   (at your option) any later version.								   *
 *																		 *
 *   This program is distributed in the hope that it will be useful,	   *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of		*
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the		 *
 *   GNU General Public License for more details.						  *
 *																		 *
 *   You should have received a copy of the GNU General Public License	 *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <server/server.h>
#include <target/target.h>
#include "ipdbg.h"
#include <helper/time_support.h>

#define IPDBG_MIN_NUM_OF_OPTIONS 4
#define IPDBG_MAX_NUM_OF_OPTIONS 14

/* private connection data for IPDBG */
struct ipdbg_connection {
	size_t dn_buf_cnt;
	size_t up_buf_cnt;
	char dn_buffer[IPDBG_BUFFER_SIZE];
	char up_buffer[IPDBG_BUFFER_SIZE];
};

struct ipdbg_service{
	struct ipdbg_hub *hub;
	struct ipdbg_service *next;
	const char *port;
	struct ipdbg_connection *connection;
	bool is_active;
	uint8_t tool;
};

struct virtual_ir_info
{
	uint32_t instruction;
	uint32_t length;
	uint32_t value;
};

struct ipdbg_hub
{
	uint32_t user_instruction;
	uint32_t max_tools;
	uint32_t active_connections;
	uint32_t active_services;
	uint32_t valid_mask;
	uint32_t tool_mask;
	struct ipdbg_hub *next;
	struct jtag_tap *tap;
	struct connection **connections;
	uint8_t data_register_length;
	struct virtual_ir_info *virtual_ir;
};

static int max_tools_from_data_register_length(uint8_t data_register_length)
{
	int max_tools = 1;
	data_register_length -= 9; // 8 bit payload, 1 valid-flag
	while(data_register_length--)
		max_tools *= 2;

	return max_tools - 1; // last tool is used to reset JtagCDC
}

static struct ipdbg_hub *ipdbg_first_hub;

static struct ipdbg_service *ipdbg_first_service;

static struct ipdbg_service *ipdbg_find_service(struct ipdbg_hub *hub, uint8_t tool)
{
	struct ipdbg_service *service;
	for(service = ipdbg_first_service ; service ; service = service->next){
		if(service->hub == hub && service->tool == tool)
			break;
	}
	return service;
}

static void ipdbg_add_service(struct ipdbg_service *service)
{
	struct ipdbg_service *iservice;
	if(ipdbg_first_service != NULL){
		for(iservice = ipdbg_first_service ; iservice->next; iservice = iservice->next);
		iservice->next = service;
	}
	else
		ipdbg_first_service = service;
}

static int ipdbg_create_service(struct ipdbg_hub *hub, uint8_t tool, struct ipdbg_service **service, const char *port)
{
	*service = malloc(sizeof(struct ipdbg_service));
	if(*service == NULL)
		return -ENOMEM;

	(*service)->hub = hub;
	(*service)->tool = tool;
	(*service)->next = NULL;
	(*service)->connection = NULL;
	(*service)->is_active = false;
	(*service)->port = malloc(strlen(port)+1);

	if((*service)->port == NULL)
	{
		free(*service);
		return -ENOMEM;
	}
	char *sport = (char *)((*service)->port);
	strcpy(sport, port);

	return ERROR_OK;
}

static void ipdbg_free_service(struct ipdbg_service *service)
{
	if(service == NULL) return;
	if(service->port)
		free((char *)service->port);
	free(service);
}

static int ipdbg_remove_service(struct ipdbg_service *service)
{
	if(ipdbg_first_service == NULL)
		return ERROR_FAIL;

	if(service == ipdbg_first_service){
		ipdbg_first_service = ipdbg_first_service->next;
		return ERROR_OK;
	}

	for(struct ipdbg_service *iservice = ipdbg_first_service ; iservice->next ; iservice = iservice->next){
		if (service == iservice->next){
			iservice->next = service->next;
			return ERROR_OK;
		}
	}

	return ERROR_FAIL;
}

static struct ipdbg_hub *ipdbg_find_hub(struct jtag_tap *tap, uint32_t user_instruction, struct virtual_ir_info *virtual_ir)
{
	struct ipdbg_hub *hub;
	for(hub = ipdbg_first_hub ; hub ; hub = hub->next){
		if(hub->tap == tap && hub->user_instruction == user_instruction){
			if((!virtual_ir && !hub->virtual_ir) ||
			(virtual_ir && hub->virtual_ir &&
				virtual_ir->instruction == hub->virtual_ir->instruction &&
				virtual_ir->length == hub->virtual_ir->length &&
				virtual_ir->value == hub->virtual_ir->value)){
				break;
			}
		}
	}
	return hub;
}

static void ipdbg_add_hub(struct ipdbg_hub *hub)
{
	struct ipdbg_hub *ihub;
	if(ipdbg_first_hub != NULL){
		for(ihub = ipdbg_first_hub ; ihub->next; ihub = ihub->next);
		ihub->next = hub;
	}
	else
		ipdbg_first_hub = hub;
}

static int ipdbg_create_hub(struct jtag_tap *tap, uint32_t user_instruction, uint8_t data_register_length, struct virtual_ir_info *virtual_ir, struct ipdbg_hub **hub)
{
	*hub = NULL;
	struct ipdbg_hub *new_hub = malloc(sizeof(struct ipdbg_hub));
	if (new_hub == NULL){
		if(virtual_ir) free(virtual_ir);
		return -ENOMEM;
	}

	new_hub->tap                  = tap;
	new_hub->user_instruction     = user_instruction;
	new_hub->data_register_length = data_register_length;
	new_hub->max_tools            = max_tools_from_data_register_length(data_register_length) ;
	new_hub->valid_mask           = 1 << (data_register_length - 1);
	new_hub->tool_mask            = (new_hub->valid_mask - 1) >> 8;
	new_hub->active_connections   = 0;
	new_hub->active_services      = 0;
	new_hub->virtual_ir           = virtual_ir;
	new_hub->next                 = NULL;
	new_hub->connections          = malloc( new_hub->max_tools * sizeof(struct connection*) );
	if(new_hub->connections == NULL){
		if(virtual_ir) free(virtual_ir);
		free(new_hub);
		return -ENOMEM;
	}
	memset(new_hub->connections, 0, new_hub->max_tools * sizeof(struct connection*));

	*hub = new_hub;
	return ERROR_OK;
}

static void ipdbg_free_hub(struct ipdbg_hub *hub)
{
	if(hub == NULL) return;
	if(hub->connections)
		free(hub->connections);
	if(hub->virtual_ir)
		free(hub->virtual_ir);
	free(hub);
}

static int ipdbg_remove_hub(struct ipdbg_hub *hub)
{
	if(ipdbg_first_hub == NULL)
		return ERROR_FAIL;
	if(hub == ipdbg_first_hub){
		ipdbg_first_hub = ipdbg_first_hub->next;
		return ERROR_OK;
	}

	for(struct ipdbg_hub *ihub = ipdbg_first_hub ; ihub->next ; ihub = ihub->next){
		if (hub == ihub->next){
			ihub->next = hub->next;
			return ERROR_OK;
		}
	}

	return ERROR_FAIL;
}

static int ipdbg_shift_instr(struct ipdbg_hub *hub, uint32_t instr)
{
	if (hub == NULL)
		return ERROR_FAIL;

	struct jtag_tap *tap = hub->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	if (buf_get_u32(tap->cur_instr, 0, tap->ir_length) != instr) {

		uint8_t *ir_val = calloc(DIV_ROUND_UP(tap->ir_length, 8), 1);
		buf_set_u32(ir_val, 0, tap->ir_length, instr);
		jtag_add_plain_ir_scan(tap->ir_length, ir_val, NULL, TAP_IDLE);

		free(ir_val);
	}

	return ERROR_OK;
}

static int ipdbg_shift_vir(struct ipdbg_hub *hub)
{
	if (hub == NULL)
		return ERROR_FAIL;

	if (!hub->virtual_ir)
		return ERROR_OK;

	if(ipdbg_shift_instr(hub, hub->virtual_ir->instruction) != ERROR_OK)
		return ERROR_FAIL;

	struct jtag_tap *tap = hub->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	uint8_t *dr_in_val = calloc(DIV_ROUND_UP(hub->virtual_ir->length, 8), 1);
	buf_set_u32(dr_in_val, 0, hub->virtual_ir->length, hub->virtual_ir->value);

	jtag_add_plain_dr_scan(hub->virtual_ir->length, dr_in_val, NULL, TAP_IDLE);
	int retval = jtag_execute_queue();

	free(dr_in_val);

	return retval;
}

static int ipdbg_shift_data(struct ipdbg_hub *hub, uint32_t in_data, uint32_t *out_data)
{
	if (hub == NULL)
		return ERROR_FAIL;

	struct jtag_tap *tap = hub->tap;
	if (tap == NULL)
		return ERROR_FAIL;

	uint8_t *dr_in_val = calloc(DIV_ROUND_UP(hub->data_register_length, 8), 1);
	buf_set_u32(dr_in_val, 0, hub->data_register_length, in_data);

	uint8_t *dr_out_val = out_data ? calloc(DIV_ROUND_UP(hub->data_register_length, 8), 1) : NULL;

	jtag_add_plain_dr_scan(hub->data_register_length, dr_in_val, dr_out_val, TAP_IDLE);
	int retval = jtag_execute_queue();

	free(dr_in_val);
	if(dr_out_val){
		if(retval == ERROR_OK)
			*out_data = buf_get_u32(dr_out_val, 0, hub->data_register_length);
		free(dr_out_val);
	}

	return retval;
}

static void ipdbg_dist_data(struct ipdbg_hub *hub, uint32_t up)
{
	const size_t tool = (up >> 8) & hub->tool_mask;
	struct connection *conn = hub->connections[tool];
	if(!conn) return;

	struct ipdbg_connection *ipdbg_conn = conn->priv;
	if(ipdbg_conn->up_buf_cnt >= IPDBG_BUFFER_SIZE){
		connection_write(conn, ipdbg_conn->up_buffer, ipdbg_conn->up_buf_cnt);
		ipdbg_conn->up_buf_cnt = 0;
	}

	ipdbg_conn->up_buffer[ipdbg_conn->up_buf_cnt++] = up;
}

static int ipdbg_polling_callback(void *priv)
{
	struct ipdbg_hub *hub = priv;

	int ret = ipdbg_shift_vir(hub);
		if(ret != ERROR_OK) return ret;

	ret = ipdbg_shift_instr(hub, hub->user_instruction);
	if(ret != ERROR_OK)
		return ret;

	/// transfer dn buffers to jtag-hub
	unsigned empty_up_transfers = 0;
	for(size_t tool = 0 ; tool < hub->max_tools ; ++tool){
		struct connection *conn = hub->connections[tool];
		if(conn)
		{
			struct ipdbg_connection *ipdbg_conn = conn->priv;
			for (size_t i = 0 ; i < ipdbg_conn->dn_buf_cnt ; ++i){
				uint32_t dn = hub->valid_mask | ((tool & hub->tool_mask) << 8) | (0x00fful & ipdbg_conn->dn_buffer[i]);
				uint32_t up = 0;
				ret = ipdbg_shift_data(hub, dn, &up);
				if(ret != ERROR_OK) return ret;
				if(up & hub->valid_mask){
					empty_up_transfers = 0;
					ipdbg_dist_data(hub, up);
				}
				else
					empty_up_transfers++;
			}
			ipdbg_conn->dn_buf_cnt = 0;
		}
	}

	/// some transfers to get data from jtag-hub in case there is no dn data
	while(empty_up_transfers++ < hub->max_tools ){
		uint32_t dn = 0;
		uint32_t up = 0;
		int retval = ipdbg_shift_data(hub, dn, &up);
		if(retval != ERROR_OK) return ret;
		if(up & hub->valid_mask){
			empty_up_transfers = 0;
			ipdbg_dist_data(hub, up);
		}
	}

	for(size_t tool = 0 ; tool < hub->max_tools ; ++tool){
		struct connection *conn = hub->connections[tool];
		if(conn){
			struct ipdbg_connection *ipdbg_conn = conn->priv;
			if(ipdbg_conn->up_buf_cnt > 0){
				connection_write(conn, ipdbg_conn->up_buffer, ipdbg_conn->up_buf_cnt);
				ipdbg_conn->up_buf_cnt = 0;
			}
		}
	}

	return ERROR_OK;
}

static int ipdbg_start_polling(struct ipdbg_service *service, struct connection *connection)
{
	struct ipdbg_hub *hub = service->hub;
	hub->connections[service->tool] = connection;
	hub->active_connections++;
	if(hub->active_connections == 1){
		uint32_t resetHub = hub->valid_mask | ((hub->max_tools) << 8);
		int ret = ipdbg_shift_vir(hub);
		if(ret != ERROR_OK) return ret;
		ret = ipdbg_shift_data(hub, resetHub, NULL);
		if(ret != ERROR_OK) return ret;
		const int time_ms = 20;
		const int periodic = 1;

		log_printf_lf( LOG_LVL_INFO, __FILE__, __LINE__, __func__,
			"IPDBG ipdbg_start_polling");


		return target_register_timer_callback(ipdbg_polling_callback, time_ms, periodic, hub);
	}
	return ERROR_OK;
}

static int ipdbg_stop_polling(struct ipdbg_service *service, struct connection *connection)
{
	struct ipdbg_hub *hub = service->hub;
	hub->connections[service->tool] = NULL;
	hub->active_connections--;
	if (hub->active_connections == 0)
	{
		log_printf_lf( LOG_LVL_INFO, __FILE__, __LINE__, __func__,
			"IPDBG ipdbg_stop_polling");

		return target_unregister_timer_callback(ipdbg_polling_callback, hub);
	}

	return ERROR_OK;
}

static int ipdbg_new_connection(struct connection *connection)
{
	struct ipdbg_connection *ipdbg_con = malloc(sizeof(struct ipdbg_connection));
	if (ipdbg_con == NULL)
		return -ENOMEM;

	connection->priv = ipdbg_con;

	/* initialize ipdbg connection information */
	ipdbg_con->dn_buf_cnt = 0;
	ipdbg_con->up_buf_cnt = 0;

	struct ipdbg_service *service = connection->service->priv;

	service->connection = ipdbg_con;

	ipdbg_start_polling(service, connection);

	log_printf_lf( LOG_LVL_INFO, __FILE__, __LINE__, __func__,
		"New IPDBG Connection");

	return ERROR_OK;
}

static int ipdbg_input(struct connection *connection)
{
	int bytes_read;
	struct ipdbg_connection *ipdbg_con = connection->priv;

	bytes_read = connection_read(connection,
								ipdbg_con->dn_buffer + ipdbg_con->dn_buf_cnt,
								IPDBG_BUFFER_SIZE - ipdbg_con->dn_buf_cnt);
	if (bytes_read == 0)
		return ERROR_SERVER_REMOTE_CLOSED;
	else if (bytes_read == -1) {
		LOG_ERROR("error during read: %s", strerror(errno));
		return ERROR_SERVER_REMOTE_CLOSED;
	}

	ipdbg_con->dn_buf_cnt += bytes_read;

	/* we'll recover from any other errors(e.g. temporary timeouts, etc.) */
	return ERROR_OK;
}

static int ipdbg_connection_closed(struct connection *connection)
{
	struct ipdbg_connection *ipdbg_con = connection->priv;
	connection->priv = NULL;
	if (ipdbg_con)
		free(ipdbg_con);
	else
		LOG_ERROR("BUG: connection->priv == NULL");

	log_printf_lf( LOG_LVL_INFO, __FILE__, __LINE__, __func__,
		"Closed IPDBG Connection ");

	struct ipdbg_service *service = connection->service->priv;
	service->connection = NULL;

	return ipdbg_stop_polling(service, connection);
}

static int ipdbg_start(const char *port, struct jtag_tap *tap, uint32_t user_instruction, uint8_t data_register_length, struct virtual_ir_info *virtual_ir, uint8_t tool)
{
	LOG_DEBUG("starting ipdbg service on port %s for tool %d", port, tool);

	struct ipdbg_hub *hub = ipdbg_find_hub(tap, user_instruction, virtual_ir);
	if( hub ){
		if(hub->data_register_length != data_register_length){
			LOG_DEBUG("hub must have the same data_register_length for all tools");
			if(virtual_ir) free(virtual_ir);
			return ERROR_FAIL;
		}
	}else{
		int retval = ipdbg_create_hub(tap, user_instruction, data_register_length, virtual_ir, &hub);
		if(retval != ERROR_OK)
			return retval;
	}

	struct ipdbg_service *service = NULL;
	int retval = ipdbg_create_service(hub, tool, &service, port);

	if(retval != ERROR_OK || service == NULL){
		if(hub->active_services == 0 && hub->active_connections == 0)
			ipdbg_free_hub(hub);
		return -ENOMEM;
	}

	retval = add_service("ipdbg", port, 1, &ipdbg_new_connection,
		&ipdbg_input, &ipdbg_connection_closed, service);
	if (retval == ERROR_OK){
		service->is_active = true;
		ipdbg_add_service(service);
		if (hub->active_services == 0 && hub->active_connections == 0)
			ipdbg_add_hub(hub);
		hub->active_services++;
	}else{
		if(hub->active_services == 0 && hub->active_connections == 0)
			ipdbg_free_hub(hub);
		ipdbg_free_service(service);
	}

	return retval;
}

static int ipdbg_stop(struct jtag_tap *tap, uint32_t user_instruction, struct virtual_ir_info *virtual_ir, uint8_t tool)
{
	struct ipdbg_hub *hub = ipdbg_find_hub(tap, user_instruction, virtual_ir);
	if(virtual_ir) free(virtual_ir);
	if(hub == NULL) return ERROR_FAIL;

	struct ipdbg_service *service = ipdbg_find_service(hub, tool);
	if(service == NULL) return ERROR_FAIL;

	int retval = remove_service("ipdbg", service->port);
	if (retval == ERROR_OK){
		service->is_active = false;
		hub->active_services--;
		if(hub->active_connections == 0 && hub->active_services == 0){
			ipdbg_remove_hub(hub);
			ipdbg_free_hub(hub);
		}
		if(service->connection == NULL)
			ipdbg_remove_service(service);
			// service will be freed by remove_service
	}else
		LOG_ERROR("BUG: remove_service failed");

	return retval;
}

COMMAND_HANDLER(handle_ipdbg_command)
{
	struct jtag_tap *tap = NULL;
	const char *port = "4242";
	uint8_t tool = 1;
	uint32_t user_instruction = 0x00;
	uint8_t data_register_length = 12;
	bool start = true;
	bool hub_configured = false;
	bool virtual_ir_given = false;
	uint32_t virtual_ir_instruction = 0x00e;
	uint32_t virtual_ir_length = 5;
	uint32_t virtual_ir_value = 0x11;
	struct virtual_ir_info *virtual_ir = NULL;

	if ((CMD_ARGC < IPDBG_MIN_NUM_OF_OPTIONS) || (CMD_ARGC > IPDBG_MAX_NUM_OF_OPTIONS))
		return ERROR_COMMAND_SYNTAX_ERROR;

	for (unsigned int i = 0; i < CMD_ARGC; ++i){
		if(strcmp(CMD_ARGV[i], "-tap") == 0){
			if (i+1 < CMD_ARGC){
				tap = jtag_tap_by_string(CMD_ARGV[i+1]);
				if (!tap) {
					command_print(CMD, "Tap: %s unknown", CMD_ARGV[i+1]);
					return ERROR_FAIL;
				}
				++i;
			}
			else
			{
				command_print(CMD, "no TAP given");
				return ERROR_FAIL;
			}
		}
		else if (strcmp(CMD_ARGV[i], "-hub") == 0){
			if (i+1 < CMD_ARGC){
				COMMAND_PARSE_NUMBER(u32, CMD_ARGV[i+1], user_instruction);
				if(i+2 < CMD_ARGC && CMD_ARGV[i+2][0] != '-'){
						COMMAND_PARSE_NUMBER(u8, CMD_ARGV[i+2], data_register_length);
						if(data_register_length < 10 || data_register_length > 32)
						{
							command_print(CMD, "length of \"user\"-data register must be at least 10 and at most 32.");
							return ERROR_FAIL;
						}
						++i;
				}
				hub_configured = true;
				++i;
			}
			else
			{
				command_print(CMD, "no \"user\"-instruction register given");
				return ERROR_FAIL;
			}
		}
		else if (strcmp(CMD_ARGV[i], "-vir") == 0){
			if (i+1 < CMD_ARGC && CMD_ARGV[i+1][0] != '-'){
				COMMAND_PARSE_NUMBER(u32, CMD_ARGV[i+1], virtual_ir_value);
				++i;
			}
			if (i+1 < CMD_ARGC && CMD_ARGV[i+1][0] != '-'){
				COMMAND_PARSE_NUMBER(u32, CMD_ARGV[i+1], virtual_ir_length);
				++i;
			}
			if (i+1 < CMD_ARGC && CMD_ARGV[i+1][0] != '-'){
				COMMAND_PARSE_NUMBER(u32, CMD_ARGV[i+1], virtual_ir_instruction);
				++i;
			}
			virtual_ir_given = true;
		}
		else if (strcmp(CMD_ARGV[i], "-port") == 0){
			if (i+1 < CMD_ARGC){
				port = CMD_ARGV[i+1];
				++i;
			}
			else
			{
				command_print(CMD, "no port given");
				return ERROR_FAIL;
			}
		}
		else if (strcmp(CMD_ARGV[i], "-tool") == 0){
			if (i+1 < CMD_ARGC){
				COMMAND_PARSE_NUMBER(u8, CMD_ARGV[i+1], tool);
				++i;
			}
		}
		else if (strcmp(CMD_ARGV[i], "-stop") == 0){
			start = false;
		}
	}

	if (!hub_configured){
		command_print(CMD, "hub not configured correctly");
		return ERROR_FAIL;
	}

	if(tool >= max_tools_from_data_register_length(data_register_length)){
		command_print(CMD, "Tool: %d is invalid", tool);
		return ERROR_FAIL;
	}

	if(virtual_ir_given){
		virtual_ir = malloc(sizeof(struct virtual_ir_info));
		if ( virtual_ir == NULL )
			return -ENOMEM;
	}

	if (start)
		return ipdbg_start(port, tap, user_instruction, data_register_length, virtual_ir, tool);
	else
		return ipdbg_stop(tap, user_instruction, virtual_ir, tool);
}

static const struct command_registration ipdbg_command_handlers[] = {
	{
		.name = "ipdbg",
		.handler = handle_ipdbg_command,
		.mode = COMMAND_EXEC,
		.help = "Starts or stops an IPDBG JTAG-Host server.",
		.usage = "[-start|-stop] -tap device.tap -hub ir_value [dr_length] [-port number] [-tool number] [-vir [vir_value [length [instr_code]]]]",
	},
	COMMAND_REGISTRATION_DONE
};

int ipdbg_register_commands(struct command_context *cmd_ctx)
{
	return register_commands(cmd_ctx, NULL, ipdbg_command_handlers);
}
