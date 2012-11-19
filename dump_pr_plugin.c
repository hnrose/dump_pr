/*
 * Copyright (c) 2010 Mellanox Technologies LTD. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <complib/cl_qmap.h>
#include <complib/cl_passivelock.h>
#include <opensm/osm_version.h>
#include <opensm/osm_opensm.h>
#include <opensm/osm_log.h>

#define DUMP_PR_FILENAME "opensm-path-records.dump"
#define DUMP_PEER_FILENAME "opensm-peer-paths.dump"
#define DUMP_SW2SW_FILENAME "opensm-sw2sw-path-records.dump"

typedef struct _path_parms {
	ib_net16_t pkey;
	uint8_t mtu;
	uint8_t rate;
	uint8_t sl;
	uint8_t pkt_life;
	boolean_t reversible;
} path_parms_t;

extern ib_api_status_t
osm_get_path_params(IN osm_sa_t * sa,
		    IN const osm_port_t * p_src_port,
		    IN const uint16_t slid_ho,
		    IN const osm_port_t * p_dest_port,
		    IN const uint16_t dlid_ho,
		    OUT path_parms_t * p_parms);

/*****************************************************************************/
static FILE *
open_file(osm_opensm_t * p_osm, const char * file_name)
{
	char path[1024];
	FILE *file;

	if (*file_name == '/')
		/* file name was provided as an absolute path */
		snprintf(path, sizeof(path), "%s", file_name);
	else
		/* file name is relative to dump_files_dir */
		snprintf(path, sizeof(path), "%s/%s",
			 p_osm->subn.opt.dump_files_dir, file_name);

	OSM_LOG(&p_osm->log, OSM_LOG_DEBUG, "Opening PR dump file: %s\n", path);
	file = fopen(path, "w");
	if (!file) {
		OSM_LOG(&p_osm->log, OSM_LOG_ERROR, "ERR PR01: "
			"cannot open file \'%s\': %s\n",
			file_name, strerror(errno));
		return NULL;
	}

	chmod(path, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

	return file;
}

/*****************************************************************************/
static void
close_file(FILE * file)
{
	if (file)
		fclose(file);
}

/*****************************************************************************/
static void get_peer_sls(osm_opensm_t * p_osm, FILE * file,
			 uint16_t sw_dlid_ho, path_parms_t * sw2sw_path_parms,
			 osm_switch_t * p_src_sw, osm_switch_t * p_dest_sw)
{
	osm_physp_t *p_src_physp, *p_dest_physp, *p_src_rem_physp, *p_dest_rem_physp;
	osm_node_t *p_src_rem_node, *p_dest_rem_node;
	osm_port_t *p_src_port, *p_dest_port;
	path_parms_t path_parms;
	ib_api_status_t status;
	uint8_t last_sl = 0xff;
	uint8_t src_port_num, dest_port_num;

	for (src_port_num = 0; src_port_num < p_src_sw->num_ports;
	     src_port_num++) {
		p_src_physp = osm_node_get_physp_ptr(p_src_sw->p_node,
						     src_port_num);
		p_src_rem_physp = osm_physp_get_remote(p_src_physp);
		if (!p_src_rem_physp)
			continue;
		p_src_rem_node = osm_physp_get_node_ptr(p_src_rem_physp);
		if (p_src_rem_node->node_info.node_type == IB_NODE_TYPE_SWITCH)
			continue;

		for (dest_port_num = 0; dest_port_num < p_dest_sw->num_ports;
		     dest_port_num++) {
			p_dest_physp = osm_node_get_physp_ptr(p_dest_sw->p_node,
							      dest_port_num);
			p_dest_rem_physp = osm_physp_get_remote(p_dest_physp);
			if (!p_dest_rem_physp)
				continue;
			p_dest_rem_node = osm_physp_get_node_ptr(p_dest_rem_physp);
			if (p_dest_rem_node->node_info.node_type == IB_NODE_TYPE_SWITCH)
				continue;

			p_src_port = osm_get_port_by_guid(&p_osm->subn,
							  p_src_rem_physp->port_guid);
			p_dest_port = osm_get_port_by_guid(&p_osm->subn,
							   p_dest_rem_physp->port_guid);
			CL_ASSERT(p_src_port);
			CL_ASSERT(p_dest_port);

			status = osm_get_path_params(&p_osm->sa,
						     p_src_port,
						     cl_ntoh16(osm_physp_get_base_lid(p_src_rem_physp)),
						     p_dest_port,
						     cl_ntoh16(osm_physp_get_base_lid(p_dest_rem_physp)),
						     (void *)&path_parms);

			if (!status && path_parms.sl != last_sl) {
				fprintf(file, "0x%04X : %-2d : %-3d : %-4d\n",
					sw_dlid_ho, path_parms.sl,
					sw2sw_path_parms->mtu,
					sw2sw_path_parms->rate);
				return;
			}
		}
	}
}

/*****************************************************************************/
static void dump_path_records(osm_opensm_t * p_osm)
{
	osm_port_t *p_src_port, *p_dest_port;
	osm_node_t *p_node;
	uint16_t slid_ho, dlid_ho;
	size_t vector_size;
	osm_physp_t *p_physp;
	char *full_pr_dump;
	int is_full_pr_dump, is_opt_pr_dump;
	FILE *file = NULL, *file2 = NULL, *file3 = NULL;
	path_parms_t path_parms;
	ib_api_status_t status;

	OSM_LOG_ENTER(&p_osm->log);

	if (p_osm->routing_engine_used &&
	    p_osm->routing_engine_used->type == OSM_ROUTING_ENGINE_TYPE_TORUS_2QOS)
		is_opt_pr_dump = 1;
	else
		is_opt_pr_dump = 0;

	full_pr_dump = getenv("DUMP_FULL_PATH_RECORDS");
	if (!full_pr_dump || (*full_pr_dump == '0'))
		is_full_pr_dump = 0;
	else
		is_full_pr_dump = 1;

	if (!is_opt_pr_dump && !is_full_pr_dump)
		goto Exit;

	if (is_full_pr_dump) {
		file = open_file(p_osm, DUMP_PR_FILENAME);
		if (!file) {
			OSM_LOG(&p_osm->log, OSM_LOG_ERROR, "ERR PR02: "
				"Dumping PR file failed - couldn't open dump file\n");
			goto Exit;
		}
	}

	if (is_opt_pr_dump) {
		file2 = open_file(p_osm, DUMP_PEER_FILENAME);
		if (!file2) {
			OSM_LOG(&p_osm->log, OSM_LOG_ERROR, "ERR PR03: "
				"Dumping PR file failed - couldn't open peer dump file\n");
			goto Exit;
		}
		file3 = open_file(p_osm, DUMP_SW2SW_FILENAME);
		if (!file3) {
			OSM_LOG(&p_osm->log, OSM_LOG_ERROR, "ERR PR04: "
				"Dumping PR file failed - couldn't open switch to switch dump file\n");
			goto Exit;
		}
	}

	vector_size = cl_ptr_vector_get_size(&p_osm->subn.port_lid_tbl);
	for (p_src_port = (osm_port_t *) cl_qmap_head(&p_osm->subn.port_guid_tbl);
	     p_src_port != (osm_port_t *) cl_qmap_end(&p_osm->subn.port_guid_tbl);
	     p_src_port = (osm_port_t *) cl_qmap_next(&p_src_port->map_item)) {

		p_node = p_src_port->p_node;
		p_physp = p_src_port->p_physp;
		CL_ASSERT(p_physp->p_remote_physp);
		slid_ho = cl_ntoh16(osm_port_get_base_lid(p_src_port));

		if (file)
			fprintf(file, "%s 0x%016" PRIx64 ", base LID %d, "
				"\"%s\", port %d\n# LID  : SL : MTU : RATE\n",
				ib_get_node_type_str(p_node->node_info.node_type),
				cl_ntoh64(p_src_port->guid), slid_ho,
				p_node->print_desc, p_physp->port_num);
		if (file2 && p_node->node_info.node_type != IB_NODE_TYPE_SWITCH)
			fprintf(file2, "%s 0x%016" PRIx64 ", base LID %d, LMC %d, "
				"\"%s\", port %d\n# LID  : MTU : RATE\n",
				ib_get_node_type_str(p_node->node_info.node_type),
				cl_ntoh64(p_src_port->guid), slid_ho,
				ib_port_info_get_lmc(&p_physp->port_info),
				p_node->print_desc, p_physp->port_num);
		if (file3 && p_node->node_info.node_type == IB_NODE_TYPE_SWITCH)
			fprintf(file3, "%s 0x%016" PRIx64 ", base LID %d, "
				"\"%s\", port %d\n# LID  : SL : MTU : RATE\n",
				ib_get_node_type_str(p_node->node_info.node_type),
				cl_ntoh64(p_src_port->guid), slid_ho,
				p_node->print_desc, p_physp->port_num);

		for (dlid_ho = 1; dlid_ho < vector_size; dlid_ho++) {

			p_dest_port = (osm_port_t *) cl_ptr_vector_get(
				&p_osm->subn.port_lid_tbl, dlid_ho);

			if (!p_dest_port || !p_dest_port->p_node)
				continue;

			status = osm_get_path_params(&p_osm->sa,
						     p_src_port, slid_ho,
						     p_dest_port, dlid_ho,
						     (void *)&path_parms);

			if (!status) {
				if (file)
					fprintf(file, "0x%04X : %-2d : %-3d : %-4d\n",
						dlid_ho, path_parms.sl,
						path_parms.mtu, path_parms.rate);
				if (file2 &&
				    p_node->node_info.node_type != IB_NODE_TYPE_SWITCH &&
				    p_physp->p_remote_physp->p_node == p_dest_port->p_node)
					fprintf(file2, "0x%04X : %-3d : %-4d\n\n",
						dlid_ho, path_parms.mtu,
						path_parms.rate);
				if (file3 &&
				    p_node->node_info.node_type == IB_NODE_TYPE_SWITCH &&
				    p_dest_port->p_node->node_info.node_type == IB_NODE_TYPE_SWITCH)
					get_peer_sls(p_osm, file3,
						     dlid_ho, &path_parms,
						     p_node->sw,
						     p_dest_port->p_node->sw);
			} else {
				if (file &&
				    p_node->node_info.node_type != IB_NODE_TYPE_SWITCH)
					fprintf(file, "0x%04X : UNREACHABLE\n",
						dlid_ho);
			}
		}
		if (file)
			fprintf(file, "\n");
		if (file3 &&
		    p_node->node_info.node_type == IB_NODE_TYPE_SWITCH)
			fprintf(file3, "\n");
	}

Exit:
	close_file(file3);
	close_file(file2);
	close_file(file);
	OSM_LOG_EXIT(&p_osm->log);
}

/*****************************************************************************/
static void *construct(osm_opensm_t *p_osm)
{
	if (p_osm->subn.opt.event_plugin_options)
		OSM_LOG(&p_osm->log, OSM_LOG_INFO,
			"Dumping PR file plugin option: \"%s\"\n",
			p_osm->subn.opt.event_plugin_options);
	return (void *)p_osm;
}

/*****************************************************************************/
static void destroy(void *p_osm)
{
	/* nothing to destroy - we didn't allocate anything */
}

/*****************************************************************************/
static void report(void *_osm, osm_epi_event_id_t event_id, void *event_data)
{
	osm_opensm_t *p_osm = (osm_opensm_t *)_osm;

	if (event_id == OSM_EVENT_ID_SUBNET_UP ||
	    event_id == OSM_EVENT_ID_UCAST_ROUTING_DONE) {
		OSM_LOG(&p_osm->log, OSM_LOG_VERBOSE, "Dump PR: %s reported\n",
			(event_id == OSM_EVENT_ID_SUBNET_UP) ?
			"Subnet Up" : "Routing Done");
		dump_path_records(p_osm);
	}
}

/*****************************************************************************
 * Define the object symbol for loading
 */

#if OSM_EVENT_PLUGIN_INTERFACE_VER != 2
#error OpenSM plugin interface version missmatch
#endif

osm_event_plugin_t osm_event_plugin = {
      osm_version:OSM_VERSION,
      create:construct,
      destroy:destroy,
      report:report
};
