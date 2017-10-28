#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <unistd.h>
#include <iconv.h>
#include <sys/stat.h>

/* Header files */
#include <openssl/des.h>
#include <openssl/sha.h>

#include "global.h"

#define BUFSIZE 2048

/* Plain text of des key */
#define KEY		"freesvr!@#"

int
code_convert(char *from_charset, char *to_charset, char *inbuf, size_t inlen, char *outbuf,
			 size_t outlen)
{
	iconv_t cd;
	char **pin = &inbuf;
	char **pout = &outbuf;

	cd = iconv_open(to_charset, from_charset);

	if (cd == 0)
		return -1;

	if (iconv(cd, pin, (size_t *) & inlen, pout, (size_t *) & outlen) == -1)
	{
		perror("iconv");
		return -1;
	}

	iconv_close(cd);
	return 0;
}

char *
g2u(char *inbuf)
{
	size_t outlen = 1024, inlen = strlen(inbuf);
	static char outbuf[1024];

	bzero(outbuf, sizeof(outbuf));
	if (code_convert("GB2312", "UTF-8", inbuf, inlen, outbuf, outlen) == 0)
		return outbuf;
	else
		return NULL;
}

void
print_hex(unsigned char *buf, int len)
{
}

int
initial_key_ivec(DES_cblock key, DES_cblock ivec)
{
	SHA_CTX sha1;
	int size;
	/* Output of SHA1 algorithm, must be 20 bytes */
	unsigned char sha1_hash[20];

	/* Initial SHA1 */
	SHA1_Init(&sha1);
	/* SHA1 encrypt */
	SHA1_Update(&sha1, KEY, strlen(KEY));
	/* Clean up */
	SHA1_Final(sha1_hash, &sha1);

	/* Print the cipher text */
	print_hex(sha1_hash, 20);

	memcpy(key, &sha1_hash[0], 8);
	memcpy(ivec, &sha1_hash[12], 8);

	return 0;
}

int
decrypt(const char *cipher, char *plain, int cipher_len, int *plain_len)
{
	DES_key_schedule schedule;
	DES_cblock key, ivec;
	int i = 0, plen;
	unsigned char input[BUFSIZE], output[BUFSIZE];

	memset(input, 0x00, BUFSIZE);
	memset(output, 0x00, BUFSIZE);
	memset(&schedule, 0x00, sizeof(DES_key_schedule));
	memset(key, 0x00, sizeof(DES_cblock));
	memset(ivec, 0x00, sizeof(DES_cblock));

	initial_key_ivec(key, ivec);
	DES_set_key_unchecked(&key, &schedule);

	memcpy((char *) input, cipher, cipher_len);
	print_hex(input, cipher_len);
	DES_ncbc_encrypt(input, output, cipher_len, &schedule, &ivec, 0);
	plen = strlen((const char *) output);
	print_hex(output, plen);

	if (plain != NULL)
	{
		memcpy(plain, (const char *) output, plen);
	}

	if (plain_len != NULL)
	{
		*plain_len = plen;
	}

	return 0;
}

int
encrypt(const char *plain, char *cipher, int plain_len, int *cipher_len)
{
	DES_key_schedule schedule;
	DES_cblock key, ivec;
	int i = 0, clen;
	unsigned char input[BUFSIZE], output[BUFSIZE];

	memset(input, 0x00, BUFSIZE);
	memset(output, 0x00, BUFSIZE);
	memset(&schedule, 0x00, sizeof(DES_key_schedule));
	memset(key, 0x00, sizeof(DES_cblock));
	memset(ivec, 0x00, sizeof(DES_cblock));

	initial_key_ivec(key, ivec);
	DES_set_key_unchecked(&key, &schedule);

	memcpy((char *) input, plain, plain_len);
	print_hex(input, plain_len);
	DES_ncbc_encrypt(input, output, plain_len, &schedule, &ivec, 1);
	clen = (plain_len + 7) / 8 * 8;
	print_hex(output, clen);

	if (cipher != NULL)
	{
		memcpy(cipher, (const char *) output, clen);
	}

	if (cipher_len != NULL)
	{
		*cipher_len = clen;
	}

	return 0;
}

int
connect2agent(const char *ip, const char *username, const char *password, int *result)
{
	int connect_fd, times = config.retry_times;
	int ret, i, len, cu_len, cp_len, mlen;
	char snd_buf[BUFSIZE], cip_buf[BUFSIZE], rcv_buf[BUFSIZE];
	struct timeval socket_timeout = { config.timeout, 0 };
	u_short ulen;
	static struct sockaddr_in srv_addr;

	connect_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (connect_fd < 0)
	{
		perror("Can't create communication socket to windows agent.");
		return -1;
	}

	memset(&srv_addr, 0, sizeof(srv_addr));
	srv_addr.sin_family = AF_INET;
	srv_addr.sin_addr.s_addr = inet_addr(ip);
	srv_addr.sin_port = htons(36137);

	ret =
		setsockopt(connect_fd, SOL_SOCKET, SO_SNDTIMEO, (char *) &socket_timeout,
				   sizeof(socket_timeout));
	ret =
		setsockopt(connect_fd, SOL_SOCKET, SO_RCVTIMEO, (char *) &socket_timeout,
				   sizeof(socket_timeout));
	ret = -1;
	while (ret != 0 && times-- > 0)
		ret = connect(connect_fd, (struct sockaddr *) &srv_addr, sizeof(srv_addr));

	if (ret == -1)
	{
		fprintf(stderr, "Can't connect to the windows server.");
		close(connect_fd);
		return -1;
	}

	memset(snd_buf, 0x00, sizeof(snd_buf));

	fprintf(stderr, "sizeof u_short is %d\n", sizeof(u_short));
	/* Pad type */
	snd_buf[0] = 0x01;
	/* Encrypt username */
	encrypt(username, cip_buf, strlen(username), &cu_len);
	/* Get the length of username's cipher */
	ulen = htons(cu_len);
	/* Pad length of username's cipher */
	memcpy(&snd_buf[1], &ulen, sizeof(u_short));
	/* Pad username's cipher */
	memcpy(&snd_buf[3], cip_buf, cu_len);
	/* Encrypt password */
	encrypt(password, cip_buf, strlen(password), &cp_len);
	/* Get the length of password's cipher */
	ulen = htons(cp_len);
	/* Pad length of password's cipher */
	memcpy(&snd_buf[1 + sizeof(u_short) + cu_len], &ulen, sizeof(u_short));
	/* Pad password's cipher */
	memcpy(&snd_buf[1 + sizeof(u_short) * 2 + cu_len], cip_buf, cp_len);

	/* Send modify password request */
	send(connect_fd, snd_buf, 1 + cu_len + cp_len + sizeof(u_short) * 2, 0);

	sleep(1);

	/* Recv type */
	ret = recv(connect_fd, rcv_buf, 1, 0);
	if (ret == 0)
	{
		fprintf(stderr, "Peer shutdown.\n");
		return -1;
	}
	else if (ret == -1)
	{
		fprintf(stderr, "An error occurred when recv the reply type from agent.\n");
		return -1;
	}
	else if (rcv_buf[0] != 0x02)
	{
		fprintf(stderr, "Recv an unknown type from agent.\n");
		return -1;
	}

	/* Recv state */
	ret = recv(connect_fd, rcv_buf, 1, 0);
	if (ret == 0)
	{
		fprintf(stderr, "Peer shutdown when recv the state from agent.\n");
		return -1;
	}
	else if (ret == -1)
	{
		fprintf(stderr, "An error occurred when recv the state from agent.\n");
		return -1;
	}

	if (result != NULL)
		*result = (int) rcv_buf[0];

	/* Recv message length */
	ret = recv(connect_fd, &ulen, sizeof(u_short), 0);
	if (ret == 0)
	{
		fprintf(stderr, "Peer shutdown when recv the msg length from agent.\n");
		return -1;
	}
	else if (ret == -1)
	{
		fprintf(stderr, "An error occurred when recv the msg length from agent.\n");
		return -1;
	}

	/* Get msg length */
	mlen = ntohs(ulen);

	/* Recv message */
	memset(rcv_buf, 0x00, sizeof(rcv_buf));
	ret = recv(connect_fd, rcv_buf, mlen, 0);
	if (ret == 0)
	{
		fprintf(stderr, "Peer shutdown when recv the message from agent.\n");
		return -1;
	}
	else if (ret == -1)
	{
		fprintf(stderr, "An error occurred when recv the message from agent.\n");
		return -1;
	}

	memset(cip_buf, 0x00, sizeof(cip_buf));
	decrypt(rcv_buf, cip_buf, mlen, &len);

	fprintf(stderr, "msg length = %d\n%s", len, g2u(cip_buf));

	close(connect_fd);
	return 0;
}

int
modify_windows_password(const Info * info)
{
	int ret, res;
	ret = connect2agent(info->device_serverip, info->device_username, info->modify_password, &res);

	if (ret != 0)
	{
		fprintf(stderr, "A communication error occurred.\n");
		update_mysql(info, 0);
	}
	else
	{
		if (res == 0)
		{
			fprintf(stderr, "Agent don't execute command.\n");
		}
		else if (res == 1)
		{
			fprintf(stderr, "Agent has executed command successfully.\n");
		}
		else if (res == 2)
		{
			fprintf(stderr, "Agent has executed command, but failed.\n");
		}

		update_mysql(info, (res == 1) ? 1 : 0);
	}

	return 0;
}

/*int main()
  {
  modify_windows_password( "222.35.62.177", "asd", "pwd" );
  return 0;
  }
*/
