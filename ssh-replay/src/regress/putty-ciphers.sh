#	$OpenBSD: putty-ciphers.sh,v 1.3 2008/11/10 02:06:35 djm Exp $
#	Placed in the Public Domain.

tid="putty ciphers"

DATA=/bin/ls
COPY=${OBJ}/copy

if test "x$REGRESS_INTEROP_PUTTY" != "xyes" ; then
	echo "putty interop tests not enabled"
	exit 0
fi

for c in aes blowfish 3des arcfour aes128-ctr aes192-ctr aes256-ctr ; do
	verbose "$tid: cipher $c"
	cp ${OBJ}/.putty/sessions/localhost_proxy \
	    ${OBJ}/.putty/sessions/cipher_$c
	echo "Cipher=$c" >> ${OBJ}/.putty/sessions/cipher_$c

	rm -f ${COPY}
	env HOME=$PWD ${PLINK} -load cipher_$c -batch -i putty.rsa2 \
	    127.0.0.1 cat ${DATA} > ${COPY}
	if [ $? -ne 0 ]; then
		fail "ssh cat $DATA failed"
	fi
	cmp ${DATA} ${COPY}		|| fail "corrupted copy"
done
rm -f ${COPY}

