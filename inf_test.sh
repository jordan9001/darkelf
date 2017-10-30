#!/bin/bash

if [ -z $1 ]; then
	echo "Usage : $0 ./test/elf"
	exit -1
elif [ ! -f $1 ]; then
	echo "File \"$1\"not found"
	exit -1
fi

inffile="${1}_infected"

cp $1 $inffile

echo "infecting $inffile"

./infector $inffile ./testing/testso.so sayit
exit $?
