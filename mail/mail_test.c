#include <stdio.h>
#include <string.h>
#if 1
#include "base64.h"
#include "send_mail.h"

int
lib_send_mail(const char *to, const char *mailserver, const char *account,
			  const char *password, const char *subject, const char *content, const char *att)
{
	int r = 0;
	struct st_mail_msg_ mail;
	struct st_char_arry to_addrs[1];
	char to_addr[64], from_addr[64];

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
	mail.server = (char *) mailserver;	// "smtp.126.com";
	mail.port = 25;
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

	return r;
}
#endif
int
main(int argc, char *argv[])
{
	// test_mail();
	int ret =
		//lib_send_mail("14769579@qq.com", "smtp.126.com", "keeplifer@126.com", "marsec",
		lib_send_mail("zz.ustc@aliyun.com", "smtp.aliyun.com", "zz.ustc@aliyun.com", "rvzz6@2v",
					  "freesvr dangerous command alarm mail", "admin run command 'pwd' on device '172.16.210.249:2288' as the account 'monitor' in session 222894", 0);
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
