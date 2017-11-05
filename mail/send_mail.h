#ifndef __SEND_MAIL_H
#define __SEND_MAIL_H

#include <stdio.h>

/* The format of mail is HTML */
#define HTML_STYLE_MAIL    				0x01

/* Send mail with Authentication */
#define AUTH_SEND_MAIL    				0x01

#define SEND_RESULT_SUCCESS    			0x00
#define SEND_RESULT_OPEN_SOCK_FINAL    	0x01
#define SEND_RESULT_CONNECT_FINAL   	0x02
#define SEND_RESULT_FINAL    			0x03
#define READ_FILE_LEN   				1024
#define PROTOCOL 						"tcp"

#define DEBUG   1

#ifndef TEMP_DIR
#define TEMP_DIR "/tmp"
#endif

struct st_char_arry
{
    char *str_p;
};

struct st_mail_msg_
{
	/* Destination address */
    int to_addr_len;
	/* Carbon copy address */
    int cc_addr_len;
    /* Blind carbon copy address */
	int bc_addr_len;
	/* Attachment file number */
    int att_file_len;
	/* Priority */
    int priority;
	/* Mail server port */
    int port;
	/* Whether authorization or not */
    int authorization;
	/* HTML format mail */
    int mail_style_html;
    /* Mail server IP or Host */
    char *server;
    /* Subject */
    char *subject;
	/* Content */
    char *content;
	/* Username for login mail server */
    char *auth_user;
	/* Password for login mail server */
    char *auth_passwd;
	/* Char set of mail */
    char *charset;
	/* Address of sender */
    char *from;
	/* Address of sender in receiver's eyes */
    char *from_subject;

    struct st_char_arry *to_address_ary;
    struct st_char_arry *cc_address_ary;
    struct st_char_arry *bc_address_ary;
    struct st_char_arry *att_file_ary;
};

void init_mail_msg( struct st_mail_msg_ *msg );
int send_mail( struct st_mail_msg_ *msg_ );

#endif  //__SEND_MAIL_H
