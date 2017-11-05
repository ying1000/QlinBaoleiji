#include <stdio.h>
#include <string.h>

#include "base64.h"
#include "send_mail.h"

int
lib_send_mail(const char *to, const char *mailserver, const char *account,
			  const char *password, const char *subject, const char *content, const char *att)
{
	int r = 0;
	struct st_mail_msg_ mail;
	struct st_char_arry to_addrs[1];
	char to_addr[64], from_addr[64], *p;

	bzero(to_addr, sizeof(to_addr));
	bzero(from_addr, sizeof(from_addr));
	snprintf(to_addr, sizeof(to_addr), "<%s>", to);
	snprintf(from_addr, sizeof(from_addr), "<%s>", account);

	to_addrs[0].str_p = to_addr;
	struct st_char_arry att_files[1];
	if (att != NULL)
	{
		att_files[0].str_p = (char *) malloc(256);
		strcpy(att_files[0].str_p, att);
	}
	// att_files[0].str_p = "/home/zhangzhong/mail/base64.c";

	init_mail_msg(&mail);

	mail.authorization = AUTH_SEND_MAIL;
	mail.server = strdup(mailserver);//(char *) mailserver;	// "smtp.126.com";
	p = strchr(mail.server, ':');
	if (p == NULL)
		mail.port = 25;
	else
	{
		*p = 0x00;
		mail.port = atoi(p + 1);
	}
	//printf("%s %d\n", mail.server, mail.port);
	mail.auth_user = (char *) account;	// "freesvr@126.com";
	mail.auth_passwd = (char *) password;	// "freesvrzhang";
	mail.from = (char *) from_addr;	// "<freesvr@126.com>";
	mail.from_subject = (char *) from_addr;	// "<freesvr@126.com>";
	mail.to_address_ary = to_addrs;
	mail.to_addr_len = 1;
	mail.content = (char *) content;	// "hello world";
	mail.subject = (char *) subject;	// "test";
	mail.mail_style_html = HTML_STYLE_MAIL;
	mail.priority = 3;
	mail.att_file_len = 0;
	mail.att_file_ary = NULL;
	if (att != NULL)
	{
		mail.att_file_len = 1;
		mail.att_file_ary = att_files;
	}

	r = send_mail(&mail);

	if (DEBUG)
		printf("Send mail [%d]\n", r);
	if (mail.server != NULL)
	{
		free(mail.server);
	}

	return r;
}

#if 0
int
main(int argc, char *argv[])
{
	// test_mail();
	int ret =
		lib_send_mail("lwm_bupt@163.com", "smtp.tirank.com:543", "steven@tirank.com", "fen9123456",
					  "test", "Hello world", "base64.c");
	printf("ret = %d", ret);

	/* 
	   ret = lib_send_mail("lwm_bupt@163.com", "mail.freesvr.com.cn", "zhaosg@freesvr.com.cn",
	   "marsec", "test", "Hello world", "base64.c"); printf("ret = %d",ret);

	   ret = lib_send_mail("lwm_bupt@163.com", "mail3.ctsi.com.cn", "zhaoshigang@ctsi.com.cn",
	   "mail.2013", "test", "Hello world", "base64.c"); printf("ret = %d",ret);

	   ret = lib_send_mail("lwm_bupt@163.com", "smtp.126.com", "freesvr@126.com", "freesvrzhang",
	   "test", "Hello world", "base64.c"); printf("ret = %d",ret); */

	return 0;
}
#endif
