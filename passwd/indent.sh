#! /bin/bash

for f in $(find . -name '*.c' -or -name '*.h' -type f)
do
echo "indent \"$f\" ......"
indent $f
done
echo Done

