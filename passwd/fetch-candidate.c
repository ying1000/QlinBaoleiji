#define _XOPEN_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "mysql.h"
#include "global.h"
#include "list.h"
#include "trie.h"
#include "random.h"

MYSQL *sql_conn;
char type_protocol[64][16];
int error_code;

char password_hash[20480][128];
double time_difference(char *t);

char    aes_key[256];

int
conn2mysql(void)
{
	/* Mysql */
	sql_conn = mysql_init(NULL);
	sql_conn =
		mysql_real_connect(sql_conn, config.mysql_address, config.mysql_username,
						   config.mysql_password, config.mysql_database, 0, NULL, 0);

	if (sql_conn)
	{
		write_log("Connect to Mysql successed.");
		return 0;
	}
	else
	{
		write_log("Connect to Mysql failed.");

		if (mysql_errno(sql_conn))
		{
			write_log("Mysql ERROR: %s", mysql_error(sql_conn));
		}

		// fail_errno = MysqlConnectError;
		return -1;
	}

	/* Mysql */
}

int
query2mysql(const char *str)
{
	if (config.write_local_log)
		fprintf(stderr, "[%d] %s\n", getpid(), str);

	if (sql_conn == NULL)
	{
		write_log("[%s] Sql_conn is NULL.", __func__);
		mysql_close(sql_conn);

		if (conn2mysql() == -1)
			return -1;
	}

	if (mysql_query(sql_conn, str))	// query_error
	{
		if (mysql_error(sql_conn))
		{
			write_log("[%s] Mysql Query ERROR @ 1: %s", __func__, mysql_error(sql_conn));
		}

		mysql_close(sql_conn);

		if (conn2mysql() == -1)
			return -1;

		else
		{
			if (mysql_query(sql_conn, str))	// query_error
			{
				if (mysql_error(sql_conn))
				{
					write_log("[%s] Mysql Query ERROR @ 2: %s", __func__, mysql_error(sql_conn));
				}

				// fail_errno = MysqlQueryError;
				return -1;
			}

			write_log("[%s] Mysql Query successed @ 2.", __func__);
			return 0;
		}
	}

	write_log("[%s] Mysql Query successed @ 1.", __func__);
	return 0;
}

int
fetch_servers_device_type(const Trie * troot)
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[128], device_ip[64];
	int ret = 0, numcols, numrows, device_type, round;

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "SELECT device_ip,device_type FROM servers");

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("Query to Mysql Error, Exit.");
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	numcols = mysql_num_fields(res);
	numrows = mysql_num_rows(res);

	if (numcols != 2)
	{
		write_log("[%s]Unknown error in servers table.", __func__);
		// error_code = 12;
		ret = -1;
	}
	else if (numrows == 0)
	{
		ret = 0;
	}
	else
	{
		round = numrows;

		while (round--)
		{
			row = mysql_fetch_row(res);

			if (row[0] == NULL)
			{
				write_log("[%s]Null value for device_ip.", __func__);
				ret = -1;
				break;
			}
			else
			{
				bzero(device_ip, sizeof(device_ip));
				strcpy(device_ip, row[0]);
			}

			if (row[1] == NULL)
			{
				write_log("[%s]Null value for device_type.", __func__);
				ret = -1;
				break;
			}
			else
			{
				device_type = atoi(row[1]);
			}

			if (trie_insert(troot, device_ip, device_type, -1, NULL, NULL) == -1)
			{
				write_log("[%s]Trie insert failed.", __func__);
				ret = -1;
				break;
			}
		}

	}

	mysql_free_result(res);
	return ret;
}

int
fetch_master_username(Trie * troot)
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[512];
	int ret = 0, numcols, numrows, round;

	write_log("Entry %s", __func__);

	bzero(buf, sizeof(buf));

    if (config.udf) {
        snprintf(buf, sizeof(buf),
            "SELECT device_ip,username,udf_decrypt(cur_password) FROM devices WHERE (login_method=3 OR login_method=5"
            " OR login_method=6 OR login_method=7 OR login_method=24 OR login_method=25) AND master_user=1");
    } else {
        snprintf(buf, sizeof(buf),
            "SELECT device_ip,username,aes_decrypt(cur_password, \"%s\") FROM devices WHERE (login_method=3 OR login_method=5"
            " OR login_method=6 OR login_method=7 OR login_method=24 OR login_method=25) AND master_user=1", aes_key);
    }

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("Query to Mysql Error, Exit.");
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	numcols = mysql_num_fields(res);
	numrows = mysql_num_rows(res);

	if (numcols != 3)
	{
		write_log("[%s]Unknown error in devices table.", __func__);
		error_code = 12;
		ret = -1;
	}
	else if (numrows == 0)
	{
		ret = 0;
	}
	else
	{
		round = numrows;

		while (round--)
		{
			row = mysql_fetch_row(res);

			if (!row[0] || !row[1])
			{
				write_log("[%s]Null value for device_ip, username.", __func__);
				ret = -1;
				break;
				//continue;
			}
			else if (!row[2])
			{
				continue;
				write_log
					("[%s]: Result of cur_password column in devices table is NULL. Maybe password in Mysql is plaintext!!",
					 __func__);
				write_log
					("[%s]: Try to set encrypt flag \"NO\" in /opt/freesvr/audit/udf/etc/freesvr_udf.conf",
					 __func__);
				ret = -1;
				//break;
				//continue;
			}

			if (trie_insert(troot, row[0], -1, 1, row[1], row[2]) == -1)
			{
				write_log("[%s]Trie insert failed.", __func__);
				ret = -1;
				break;
			}
		}

	}

	mysql_free_result(res);

	return ret;
}

int
fetch_servergroup_table()
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[128];
	int ret = 0, numcols, numrows;

	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "SELECT id FROM servergroup WHERE groupname=\"%s\"", group_name);

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("Query to Mysql Error, Exit.");
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	numcols = mysql_num_fields(res);
	numrows = mysql_num_rows(res);

	if (numcols == 0 || numrows != 1)
	{
		write_log("No such groupname \"%s\" in servergroup table.", group_name);
		error_code = 10;
		ret = -1;
	}
	else if (numcols > 1 || numrows != 1)
	{
		write_log("Multiple define of groupname \"%s\" in servergroup table.", group_name);
		error_code = 11;
		ret = -1;
	}
	else
	{
		row = mysql_fetch_row(res);

		if (row[0] != NULL)
			ret = atoi(row[0]);
	}

	mysql_free_result(res);
	return ret;
}

int
hash_insert(Candidate_head * root, const Info * ic, int id)
{
	Candidate_node *p = root->next;
	Info *ip;

	while (p)
	{
		ip = &(p->servinfo);

		/* This account is already in candidate set */
		if (!strcmp(ic->device_serverip, ip->device_serverip)
			&& !strcmp(ic->device_username, ip->device_username))
		{
			ip->auto_modify = ic->auto_modify > ip->auto_modify ? ic->auto_modify : ip->auto_modify;

			if (ic->protocol < ip->protocol)
			{
				ip->protocol = ic->protocol;
				ip->device_port = ic->device_port;
				ip->device_ptcl = ic->device_ptcl;
			}

			list_insert(ip->id_list, id);

			return 0;
		}

		p = p->next;
	}

	candidate_insert(root, ic);

	return 0;
}

int
initial_info(const char *device_ip, void *addr[], Info * i, int calc_date)
{
	/* Initial struct _info */
	memset(i, 0x00, sizeof(Info));

	/* Set device ip address */
	strcpy(i->device_serverip, device_ip);

	/* Get the address of each element in struct */
	/* Get (char*) */
	addr[0] = &(i->last_modify_day);
	addr[1] = &(i->device_username);
	addr[2] = &(i->device_password);

	/* Get (int*) */
	addr[3] = &(i->device_port);
	addr[4] = &(i->device_ptcl);
	addr[5] = &(i->device_type);
	addr[6] = &(i->auto_modify);
	
	/* Set calculate date flag */
	i->calc_date = calc_date;

	/* Initial list head */
	i->id_list = list_create();

	return 0;
}

int
fetch_devices_table(Candidate_head * clist, const char *device_ip, int calc_date, int is_windows)
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[512];
	int ret = 0, i, numcols, numrows, round, device_id, login_method;
	void *addr[8];
	Info tmp_node;
	double td;

	bzero(buf, sizeof(buf));

    if (config.udf) {
        if (is_windows)
        {
            if (suser_strategy_flag)
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,udf_decrypt(cur_password),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND username=\"%s\" AND active_change>0",
                    device_ip, suser_name);
            }
            else
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,udf_decrypt(cur_password),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND active_change>0",
                    device_ip);
            }
        }
        else
        {
            if (suser_strategy_flag)
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,udf_decrypt(cur_password),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND (login_method=3 OR login_method=5"
                    " OR login_method=6 OR login_method=7 OR login_method=24 OR login_method=25) AND username=\"%s\" "
                    "AND active_change>0",
                    device_ip, suser_name);
            }
            else
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,udf_decrypt(cur_password),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND (login_method=3 OR login_method=5"
                    " OR login_method=6 OR login_method=7 OR login_method=24 OR login_method=25) "
                    "AND active_change>0",
                    device_ip);
            }
        }
    } else {
        if (is_windows)
        {
            if (suser_strategy_flag)
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,aes_decrypt(cur_password, \"%s\"),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND username=\"%s\" AND active_change>0",
                    aes_key, device_ip, suser_name);
            }
            else
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,aes_decrypt(cur_password, \"%s\"),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND active_change>0",
                    aes_key, device_ip);
            }
        }
        else
        {
            if (suser_strategy_flag)
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,aes_decrypt(cur_password, \"%s\"),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND (login_method=3 OR login_method=5"
                    " OR login_method=6 OR login_method=7 OR login_method=24 OR login_method=25) AND username=\"%s\" "
                    "AND active_change>0",
                    aes_key, device_ip, suser_name);
            }
            else
            {
                snprintf(buf, sizeof(buf),
                    "SELECT last_update_time,username,aes_decrypt(cur_password, \"%s\"),port,login_method,device_type,"
                    "automodify,id,radiususer FROM devices WHERE device_ip=\"%s\" AND entrust_password=1 "
                    "AND (login_method=3 OR login_method=5"
                    " OR login_method=6 OR login_method=7 OR login_method=24 OR login_method=25) "
                    "AND active_change>0",
                    aes_key, device_ip);
            }
        }
    }

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("Query to Mysql Error, Exit.");
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	numcols = mysql_num_fields(res);
	numrows = mysql_num_rows(res);

	if (numcols != 9)
	{
		write_log("Unknown error in devices table.");
		error_code = 12;
		ret = -1;
	}
	else if (numrows == 0)		// it needless to modify password
	{
		ret = 0;
	}
	else
	{
		round = numrows;

		while (round--)
		{
			row = mysql_fetch_row(res);
			//write_log("round=%d %s", round, row[7]);
			if (row[8] != NULL && atoi(row[8]) != 0)
			{
				if (atoi(row[6]) != 1)
					continue;
				if (calc_date != 0 && (td = time_difference(row[0])) < calc_date * 24 * 3600)
				{
					fprintf(stderr, "Time difference is %f day. Don't modify.\n", td);
					continue;
				}
				if (update_radiususer(atoi(row[8]), atoi(row[7]), row[2], row[1], device_ip) != 0)
				{
					insert_log_table(device_ip, row[1], 0);
					fprintf(stderr, "***********Update RadiusUser %s@%s Failed.\n", row[1], device_ip);
				}
				else
					fprintf(stderr, "***********Update RadiusUser %s@%s Successed.\n", row[1], device_ip);
			}
			else
			{
				initial_info(device_ip, addr, &tmp_node, calc_date);

				if (row[7] != NULL)
				{
					device_id = atoi(row[7]);
					list_insert(tmp_node.id_list, atoi(row[7]));
				}

				for (i = 0; i < 3; i++)
				{
					if (row[i] != NULL)
						strcpy(addr[i], row[i]);
				}

				for (; i < numcols - 2; i++)
				{
					//write_log("%d, %s, %p", i, row[i], addr[i]);
					if (row[i] != NULL)
						*((int *) addr[i]) = atoi(row[i]);
				}


				/* Get login_method */
				if (row[4])
					login_method = atoi(row[4]);

				if (is_windows)
				{
					tmp_node.protocol = AGENT_PROTOCOL;
				}
				else
				{
					/* Login method is neither SSH nor TELNET */
					if (login_method != 3 && login_method != 5 && login_method != 7 &&
						strncasecmp(type_protocol[login_method], "ssh1", 4) != 0)
					{
						tmp_node.protocol = UNSUPPORT_PROTOCOL;
					}
					else
					{
						if (strncasecmp(type_protocol[login_method], "ssh1", 4) == 0)
							tmp_node.protocol = SSH1_PROTOCOL;
						else if (login_method == 3 || login_method == 7)
							tmp_node.protocol = SSH2_PROTOCOL;
						else if (login_method == 5)
							tmp_node.protocol = TELNET_PROTOCOL;
						else
							tmp_node.protocol = UNSUPPORT_PROTOCOL;
					}
				}

				hash_insert(clist, &tmp_node, device_id);
			}
		}

	}

	mysql_free_result(res);
	return ret;
}

int
fetch_servers_table(Candidate_head * clist)
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	time_t t_now;
	struct tm *p;
	char buf[128];
	int ret = 0, groupid, wday, mday, windows = 0;

	bzero(buf, sizeof(buf));

	if (group_strategy_flag)	// server group strategy
	{
		groupid = atoi(group_name);//fetch_servergroup_table();

		if (groupid == -1)
		{
			return -1;
		}
		else
		{
			snprintf(buf, sizeof(buf),
					 "SELECT device_ip,device_type,month,week,user_define FROM servers WHERE groupid=%d",
					 groupid);
		}
	}
	else if (svrip_strategy_flag)	// server ip address strategy
	{
		snprintf(buf, sizeof(buf),
				 "SELECT device_ip,device_type,month,week,user_define FROM servers WHERE device_ip=\"%s\"",
				 svrip_addr);
	}
	else						// all servers
	{
		snprintf(buf, sizeof(buf),
				 "SELECT device_ip,device_type,month,week,user_define FROM servers");
	}

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("Query to Mysql Error, Exit.");
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	time(&t_now);
	p = localtime(&t_now);

	wday = p->tm_wday ? p->tm_wday : 7;
	mday = p->tm_mday;

	write_log("%d", mysql_num_rows(res));
	while ((row = mysql_fetch_row(res)) != NULL)
	{
		//write_log("%s ip=%s %p", __func__, row[0], res);
		if (row[1] != NULL && strlen(row[1])
			&& strncasecmp(type_protocol[atoi(row[1])], "win", 3) == 0)
		{
			windows = 1;
			write_log("\"%s\" is windows device.", row[0]);
		}
		else
		{
			windows = 0;
			write_log("\"%s\" is %s device.", row[0],
					  strlen(type_protocol[atoi(row[1])]) ? type_protocol[atoi(row[1])] :
					  "unknown");
		}

		if (force_strategy_flag)
		{
			fetch_devices_table(clist, row[0], 0, windows);
		}
		else if (row[2] != NULL && strlen(row[2]) && atoi(row[2]) != 0)	// month
		{
			if (atoi(row[2]) == mday)
				fetch_devices_table(clist, row[0], 0, windows);
			else
				continue;
		}
		else if (row[3] != NULL && strlen(row[3]) && atoi(row[3]) != 0)	// week
		{
			if (atoi(row[3]) == wday)
				fetch_devices_table(clist, row[0], 0, windows);
			else
				continue;
		}
		else if (row[4] != NULL && strlen(row[4]) && atoi(row[4]) != 0)	// user_define
		{
			fetch_devices_table(clist, row[0], atoi(row[4]), windows);
		}
		else
		{
			continue;
		}
		//write_log("%s end   ip=%s  %p", __func__, row[0], res);
		
	}

	//write_log("%s end", __func__);
	mysql_free_result(res);
	return ret;
}

int
fetch_login_template_table()
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[128];
	int ret = 0, index;

	bzero(buf, sizeof(buf));
	bzero(type_protocol, sizeof(type_protocol));
	snprintf(buf, sizeof(buf), "SELECT id,device_type,login_method FROM login_template");

	if (mysql_query(sql_conn, buf) == 1)
	{
		fprintf(stderr, "[%s]Query to mysql Error, Exit.\n", __func__);
		return -1;
	}

	res = mysql_store_result(sql_conn);

	while ((row = mysql_fetch_row(res)) != NULL)
	{
		if (row[0] == NULL)
		{
			fprintf(stderr, "[%s]Field \"id\" is NULL in table login_template.\n", __func__);
			ret = -1;
			break;
		}

		index = atoi(row[0]);

		if ((row[1] != NULL && strlen(row[1]) && row[2] != NULL && strlen(row[2]))
			|| (row[1] == NULL && row[2] == NULL))
		{
			fprintf(stderr,
					"[%s]Field \"device_type\" and \"login_method\" is conflict where id=%d.\n",
					__func__, index);
			ret = -1;
			break;
		}

		strcpy(type_protocol[index], ((row[1] == NULL) || (strlen(row[1]) == 0)) ? row[2] : row[1]);
	}

	mysql_free_result(res);
	write_log("Initial device_type and login_method %s.", (ret == 0) ? "successed" : "failed");
	return ret;
}

int
fetch_admin_password_email()
{
	MYSQL_RES *res = NULL;
	MYSQL_ROW row;
	char buf[128];
	int ret = 0;

	/* Fetch the email of admin */
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "SELECT email FROM member WHERE username=\"admin\"");

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("[%s]Query to mysql Error, Exit.", __func__);
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	row = mysql_fetch_row(res);

	if (row[0])
	{
		bzero(admin_email, sizeof(admin_email));
		strcpy(admin_email, row[0]);
	}
	else
	{
		write_log("Email of admin is NULL.");
		return -1;
	}

	/* Fetch the email of password */
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "SELECT email FROM member WHERE username=\"password\"");

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("[%s]Query to mysql Error, Exit.", __func__);
		return -1;
	}

	res = mysql_store_result(sql_conn);

	if (res == NULL)
	{
		write_log("[%s:%dL] Error store result: Error %d: %s\n", __FILE__, __LINE__,
				  mysql_errno(sql_conn), mysql_error(sql_conn));
		return -1;
	}

	row = mysql_fetch_row(res);

	if (row[0])
	{
		bzero(password_email, sizeof(password_email));
		strcpy(password_email, row[0]);
	}
	else
	{
		write_log("Email of password is NULL.");
		return -1;
	}

	mysql_free_result(res);
	write_log("Fetch email of admin and password %s.", (ret == 0) ? "successed" : "failed");
	return ret;
}

double
time_difference(char *t)
{
	char *p1, *p2;
	struct tm tm_time;
	time_t t_old, t_now;

	p1 = t;
	p2 = strchr(p1, '-');
	*p2 = 0x00;
	tm_time.tm_year = atoi(p1) - 1900;

	if (tm_time.tm_year < 0)
		return 10000.0 * 24 * 3600;;

	p1 = p2 + 1;
	p2 = strchr(p1, '-');
	*p2 = 0x00;
	tm_time.tm_mon = atoi(p1) - 1;

	p1 = p2 + 1;
	p2 = strchr(p1, ' ');
	*p2 = 0x00;
	tm_time.tm_mday = atoi(p1);

	p1 = p2 + 1;
	p2 = strchr(p1, ':');
	*p2 = 0x00;
	tm_time.tm_hour = atoi(p1);

	p1 = p2 + 1;
	p2 = strchr(p1, ':');
	*p2 = 0x00;
	tm_time.tm_min = atoi(p1);

	p1 = p2 + 1;
	tm_time.tm_sec = atoi(p1);

	tm_time.tm_isdst = 0;

	t_old = mktime(&tm_time);

	time(&t_now);

	return difftime(t_now, t_old);
}

int
candidate_filter(Trie * troot, Candidate_head * clist)
{
	Candidate_node *p = clist->next, *previous = clist, *current;
	Info *i;
	int device_type, have_master;
	double td;

	write_log("Entry [%s] function.", __func__);

	while (p)
	{
		current = p;
		i = &(p->servinfo);
		p = p->next;

		fprintf(stderr, "+----- Filter device \"%s@%s\" -----+\n", i->device_username,
				i->device_serverip);

		/* Filter auto modify flag */
		if (i->auto_modify != 1)
		{
			fprintf(stderr, "The automodify flag of %s@%s is %d. Don't modify.\n",
					i->device_username, i->device_serverip, i->auto_modify);
			candidate_delete(previous, current);
			continue;
		}

		/* Filter login protocol, only support ssh1, ssh2 and telnet */
		if (i->protocol == UNSUPPORT_PROTOCOL)
		{
			fprintf(stderr, "Login protocol is %s, not support. Don't modify.\n",
					type_protocol[i->device_ptcl]);
			candidate_delete(previous, current);
			continue;
		}

		/* Filter user define */
		if (i->calc_date && (td = time_difference(i->last_modify_day)) < (i->calc_date) * 24 * 3600)
		{
			fprintf(stderr, "Time difference is %f day. Don't modify.\n", td);
			candidate_delete(previous, current);
			continue;
		}

		trie_search(troot, i->device_serverip, &device_type, &have_master, i->master_username,
					i->master_password);

		/* Filter unknown device type */
		if (strlen(type_protocol[device_type]) == 0)
		{
			fprintf(stderr, "%s has unknown device type, device_type=%d. Don't modify.\n",
					i->device_serverip, device_type);
			candidate_delete(previous, current);
			continue;
		}

		/* Filter Windows OS device */
		/* if( strncasecmp( type_protocol[device_type], "win", 3 ) == 0 ) { fprintf( stderr, "%s is 
		   %s. Don't modify.\n", i->device_serverip, type_protocol[device_type] );
		   candidate_delete( previous, current ); continue; } */

		/* Set login username and password */
		if (have_master == 1 && i->protocol != AGENT_PROTOCOL)
		{
			i->have_master = 1;
		}
		else
		{
			i->have_master = 0;
		}

		/* Set new password */
		if (fixed_password_flag)
		{
			if (strlen(passphrase) == 0)
			{
				fprintf(stderr, "Fixed passphrase is NULL. Don't modify.\n");
				candidate_delete(previous, current);
				continue;
			}
			else if (specified_password_valid_check(sql_conn, i->device_password, passphrase) != 0)
			{
				fprintf(stderr, "Specified password by user is invalid, maybe it is too simple.\n");
				candidate_delete(previous, current);
				continue;
			}

			strcpy(i->modify_password, passphrase);
		}
		else
		{
			if (generate_random_password(sql_conn, i->device_password, i->modify_password) == -1)
			{
				fprintf(stderr,
						"Memory Address of modify password is NULL or password is too simple. Don't modify.\n");
				candidate_delete(previous, current);
				continue;
			}
		}

		if (i->protocol == AGENT_PROTOCOL && strlen(i->device_username) == 0)
		{
			fprintf(stderr, "NULL username in windows OS. Don't modify.\n");
			candidate_delete(previous, current);
			continue;
		}

		/* if (i->protocol == RADIUS_PROTOCOL) { fprintf(stderr, "Update Radius user. Don't
		   modify.\n"); update_radiususer(i->device_ptcl, i->device_id, i->device_username,
		   i->modify_password); candidate_delete(previous, current); continue; } */

		/* Set exec argv */
		if ((i->argv = execv_argument_create(i->device_serverip,
											 // ( have_master ? i->master_username :
											 // i->device_username ),
											 (i->have_master ? i->master_username : i->
											  device_username),
											 // ( have_master ? i->master_password :
											 // i->device_password ),
											 (i->have_master ? i->master_password : i->
											  device_password), i->protocol,
											 i->device_port)) == NULL)
		{
			fprintf(stderr, "Create exec argument failed. Don't modify.\n");
			candidate_delete(previous, current);
			continue;
		}

		/* Set command */
		fprintf(stderr, "type = %s\n", type_protocol[i->device_type]);
		if ((i->input =
			 command_list_creat(i->protocol, i->have_master, i->device_username, i->device_password,
								 i->modify_password, i->master_username, i->master_password)) == NULL)
		{
			fprintf(stderr, "Create exec argument failed. Don't modify.\n");
			candidate_delete(previous, current);
			continue;
		}

		previous = current;
		fprintf(stderr, "Go to next step.\n");
	}

	return 0;
}

int
insert_log_table(const char *device_ip, const char *username, int successed)
{
	char buf[256];

	snprintf(buf, sizeof(buf),
			"INSERT INTO log (time,device_ip,username,update_success_flag) VALUES(now(),\"%s\",\"%s\",\"%s\")",
			device_ip, username, successed ? "Yes" : "No");
	mysql_query(sql_conn, buf);
	return 0;
}

char *
shift_old_password(const char *old_password)
{
	char buf[512], *ret;
	int i, j, ilen = strlen(old_password), jlen = sizeof(buf);

	bzero(buf, sizeof(buf));
	for (i = 0, j = 0; i < ilen && j < jlen; i++, j++)
	{
		if (old_password[i] == 0x27 ||
				old_password[i] == 0x22 ||
				old_password[i] == 0x5c)
		{
			buf[j++] = 0x5c;
		}
		buf[j] = old_password[i];
	}

	ret = (char *)malloc(j * sizeof(char));
	if (ret == NULL)
		return NULL;
	bzero(ret, (j+1) * sizeof(char));
	strncpy(ret, buf, j);

	write_log("**********  %s", ret);
	return ret;
}

int
update_radiususer(int member_id, int device_id, const char *old_password, const char *username, const char *device_ip)
{
	MYSQL_RES *res;
	MYSQL_ROW row;

	char buf[256], password[256], *sp;
	int ret = 0;

	snprintf(buf, sizeof(buf), "SELECT id from radcheck WHERE UserName='%s'", username);
	mysql_query(sql_conn, buf);

	res = mysql_store_result(sql_conn);
	if (res == NULL)
		return -1;
	
	row = mysql_fetch_row(res);
	if (row == NULL || row[0] == NULL)
	{
		//insert_log_table(device_ip, username, 0);
		mysql_free_result(res);
		return -1;
	}

	mysql_free_result(res);

	bzero(password, sizeof(password));
	/* Set new password */
	if (fixed_password_flag)
	{
		if (strlen(passphrase) == 0)
		{
			fprintf(stderr, "[%s]: Fixed passphrase is NULL. Don't modify.\n", __func__);
			return -1;
		}
		else if (specified_password_valid_check(sql_conn, old_password, passphrase) != 0)
		{
			fprintf(stderr,
					"[%s]: Specified password by user is invalid, maybe it is too simple.\n",
					__func__);
			return -1;
		}

		strcpy(password, passphrase);
	}
	else
	{
		if (generate_random_password(sql_conn, old_password, password) == -1)
		{
			fprintf(stderr,
					"[%s]: Memory Address of modify password is NULL or password is too simple. Don't modify.\n",
					__func__);
			return -1;
		}
	}

	/* Check radiususer, fetch password hash */
	if (password_hash[member_id][0] == 0x00)
	{
		strcpy(password_hash[member_id], password);
	}
	else
	{
		strcpy(password, password_hash[member_id]);
	}	

	/* Update member */
	bzero(buf, sizeof(buf));

    if (config.udf) {
        snprintf(buf, sizeof(buf), "UPDATE member SET password=udf_encrypt(\"%s\") WHERE uid=%d",
            password, member_id);
    } else {
        snprintf(buf, sizeof(buf), "UPDATE member SET password=aes_encrypt(\"%s\", \"%s\") WHERE uid=%d", password, aes_key, member_id);
    }

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("[%s]Update Mysql member failed, Exit.", __func__);
		return -1;
	}

	/* Update devices */
	bzero(buf, sizeof(buf));

    if (config.udf) {
        snprintf(buf, sizeof(buf),
            "UPDATE devices SET old_password=udf_encrypt(\"%s\"),cur_password=udf_encrypt(\"%s\"),last_update_time=now() WHERE id=%d",
            (sp = shift_old_password(old_password)), password, device_id);
    } else {
        snprintf(buf, sizeof(buf),
            "UPDATE devices SET old_password=aes_encrypt(\"%s\", \"%s\"),cur_password=aes_encrypt(\"%s\", \"%s\"),last_update_time=now() WHERE id=%d",
            (sp = shift_old_password(old_password)), aes_key, password, aes_key, device_id);
    }

	free(sp);
	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("[%s]Update Mysql devices failed, Exit.", __func__);
		return -1;
	}

	/* Update radcheck */
	bzero(buf, sizeof(buf));
	snprintf(buf, sizeof(buf), "UPDATE radcheck SET Value=\"%s\" WHERE UserName=\"%s\"",
			 crypt(password, "$1$qY9g/6K4"), username);

	if (mysql_query(sql_conn, buf) == 1)
	{
		write_log("[%s]Update Mysql radcheck failed, Exit.", __func__);
		return -1;
	}
	
	insert_log_table(device_ip, username, 1);
	return 0;
}

int
id_list_printf(List_head * root)
{
	List_node *p = root->next;

	fprintf(stderr, "id: ");

	while (p)
	{
		fprintf(stderr, "%d ", p->element);
		p = p->next;
	}

	fprintf(stderr, "\n");

	return 0;
}

int
update_devices_before_modify_password(Candidate_head * root)
{
	Candidate_node *p = root->next;
	Info *ip = NULL;
	List_node *l = NULL;
	char buf[1024];

	write_log("Entry [%s] function.", __func__);

	while (p)
	{
		ip = &(p->servinfo);
		l = ip->id_list->next;

		while (l)
		{
			//update devicesid
			bzero(buf, sizeof(buf));

            if (config.udf) {
                snprintf(buf, sizeof(buf), "UPDATE devices SET active_change=2,new_password=udf_encrypt('%s') WHERE id=%d", 
                    ip->modify_password, l->element);
            } else {
                snprintf(buf, sizeof(buf), "UPDATE devices SET active_change=2,new_password=aes_encrypt('%s', '%s') WHERE id=%d",
                    ip->modify_password, aes_key, l->element);
            }

			if (mysql_query(sql_conn, buf)) // query_error
			{
				if (mysql_error(sql_conn))
				{
					write_log("[%s] Mysql Query ERROR: %s", __func__, mysql_error(sql_conn));
				}
			}	

			l = l->next;
		}

		p = p->next;
	}

	return 0;
}

int
candidate_printf(Candidate_head * root)
{
	Candidate_node *p = root->next;
    Info *ip = NULL;
    MYSQL_RES *res;
    MYSQL_ROW row;
    char buf[512];

	write_log("Entry [%s] function.", __func__);

	while (p)
	{
		ip = &(p->servinfo);
        
        bzero(buf, sizeof(buf));
        
        if (config.udf) {
            snprintf(buf, sizeof(buf), "SELECT udf_encrypt(\"%s\")", ip->modify_password);
        } else {
            snprintf(buf, sizeof(buf), "SELECT aes_encrypt(\"%s\", \"%s\")", ip->modify_password, aes_key);
        }
        
        mysql_query(sql_conn, buf);
        res = mysql_store_result(sql_conn);
        if (res != NULL)
            row = mysql_fetch_row(res);

		fprintf(stderr,
				"%-16s %-6s master:%d new_password:%-12s  login_user:%-14s modify_user:%-14s ",
				ip->device_serverip, type_protocol[ip->device_ptcl], ip->have_master,
				row[0],// "********",
				ip->have_master ? ip->master_username : ip->device_username, ip->device_username);

		id_list_printf(ip->id_list);

		p = p->next;
	}

	return 0;
}

int
candidate2modify(Login * llist, Candidate_head * root)
{
	Candidate_node *p = root->next;

	write_log("Entry [%s] function.", __func__);

	while (p)
	{

		if (login_list_insert(llist, p) == -1)
		{
			write_log("Integrate candidate list failed.");
			return -1;
		}

		p = p->next;
	}

	return 0;
}

int
modify_printf(Login * llist)
{
	Login *p = llist;
	Modify_info *m;
	Info *i;

	while (p->next)
	{
		p = p->next;
		m = p->minfo;
		fprintf(stderr, "server: %s p:%s user: ", (m->next->servinfo)->device_serverip, "********");
		// ( m->next->servinfo )->have_master ? ( m->next->servinfo )->master_password : (
		// m->next->servinfo )->device_password );

		while (m->next)
		{
			m = m->next;
			i = m->servinfo;
			fprintf(stderr, "%s, ", i->device_username);
		}

		fprintf(stderr, "\n");
	}

	return 0;
}

int
fetch_candidate(Candidate_head * clist)
{
	return fetch_servers_table(clist);
}

int
execute_modify(Login * llist)
{
	int pid;

	pid = fork();

	if (pid == -1)
		return -1;
	else if (pid == 0)
	{
		Login *p = llist;

		while (p->next)
		{
			p = p->next;
			if (p->minfo->next->servinfo->protocol == AGENT_PROTOCOL)
			{
				modify_windows_password(p->minfo->next->servinfo);
			}
			/* HuaWei devices */
			else if (strcasecmp("huawei", type_protocol[p->minfo->next->servinfo->device_type]) == 0)
			{
				fprintf(stderr, "Modify the password of Huawei device\n");
				modify_password_on_huawei_device(p->minfo);
			}
			/* H3C devices */
			else if (strcasecmp("h3c", type_protocol[p->minfo->next->servinfo->device_type]) == 0)
			{
				fprintf(stderr, "Modify the password of H3C device\n");
				modify_password_on_h3c_device(p->minfo);
			}
			/* CISCO devices */
			else if (strcasecmp("cisco", type_protocol[p->minfo->next->servinfo->device_type]) == 0)
			{
				fprintf(stderr, "Modify the password of cisco device\n");
				modify_password_on_cisco_device(p->minfo);
			}

			else
			{
				ssh_modify_password(p->minfo);
			}
		}

		password_envelope();
		return 0;
	}
	else
	{
		printf("I am parent.\n");
		return 0;
	}
}

int
fetch_aes_key()
{
    MYSQL_RES *res;
    MYSQL_ROW row;
    char buf[128];
    int ret = 0;

    bzero(buf, sizeof(buf));
    bzero(aes_key, sizeof(aes_key));
    snprintf(buf, sizeof(buf),
        "select udf_decrypt(svalue) from setting where sname=\"PasswordKey\"");

    if (mysql_query(sql_conn, buf) == 1)
    {
        fprintf(stderr, "Query to mysql Error, Exit.\n");
        return -1;
    }

    res = mysql_store_result(sql_conn);

    row = mysql_fetch_row(res);

    if (row && row[0])
        strncpy(aes_key, row[0], sizeof(aes_key));

    mysql_free_result(res);

    return ret;
}

int
process(void)
{
	Trie *troot;
	Candidate_head *clist;
	Login *llist;
	int ret = 0;

	write_log("/*********************************************/");

	set_password_alphabet();

	/* Create root of trie struct */
	if ((troot = trie_create()) == NULL)
	{
		write_log("Can't create trie structure.");
		return -1;
	}

	/* Create root of candidate list struct */
	if ((clist = candidate_create()) == NULL)
	{
		write_log("Can't create candidate list.");
		trie_destroy(troot);
		return -1;
	}

	/* Create root of Login list struct */
	if ((llist = login_list_create()) == NULL)
	{
		write_log("Can't create Login list.");
		trie_destroy(troot);
		candidate_destroy(clist);
		return -1;
	}

	/* Connect to MySQL */
	if (conn2mysql() == -1)
	{
		write_log("Can't connect to MySQL server.");
		trie_destroy(troot);
		candidate_destroy(clist);
		return -1;
	}

	/* Fetch login template table */
	if (fetch_login_template_table() == -1)
	{
		write_log("Several errors appear when fetching login_template table.");
		ret = -1;
		goto clear;
	}

    fetch_aes_key();

	/* Fetch email of admin and password */
	if (fetch_admin_password_email() == -1)
	{
		write_log("Several errors appear when fetching email.");
		ret = -1;
		goto clear;
	}

	/* Fetch device type */
	if (fetch_servers_device_type(troot) == -1)
	{
		write_log("Several errors appear when fetching device type from servers table.");
		ret = -1;
		goto clear;
	}

	/* Fetch master user */
	if (fetch_master_username(troot) == -1)
	{
		write_log("Several errors appear when fetching master user from devices table.");
		ret = -1;
		goto clear;
	}

	/* Print trie structure */
	if (trie_visited(troot, -1) == -1)
	{
		write_log("Several errors appear when printing trie structure.");
		ret = -1;
		goto clear;
	}


	if (fetch_candidate(clist) == -1)
	{
		write_log("Several errors appear when fetch candidate list.");
		ret = -1;
		goto clear;
	}

	candidate_filter(troot, clist);

	if (manual_mode == 1)
		mysql_query(sql_conn, "UPDATE devices SET active_change=1");

	update_devices_before_modify_password(clist);
	candidate_printf(clist);
	mysql_close(sql_conn);
	
	if (manual_mode == 1)
		goto clear;

	candidate2modify(llist, clist);
	modify_printf(llist);
	execute_modify(llist);

	MYSQL *sql = mysql_init(NULL);
	sql = mysql_real_connect(sql, config.mysql_address, config.mysql_username, config.mysql_password,
				config.mysql_database, 0, NULL, 0);
	mysql_query(sql, "UPDATE devices SET active_change=1");
	mysql_close(sql);


  clear:

	/* Free trie */
	trie_destroy(troot);

	/* Free list */
	candidate_destroy(clist);

	write_log("End");

	return ret;
}
