#!/bin/bash
#
# list man pages found given one or more ??? passed in
#
# copied from
#  https://github.com/linux-nvme/libnvme:doc/list-man-pages.sh
#

for file in $@; do
    for func in $(sed -n 's/ \* \([a-z_][a-z_0-9]*\)() -.*/\1/p' $file); do
	echo ${func}
    done

    for struct in $(sed -n 's/ \* struct \([a-z_]*\) -.*/\1/p' $file); do
	echo ${struct}
    done

    for enum in $(sed -n 's/ \* enum \([a-z_]*\) -.*/\1/p' $file); do
	echo ${enum}
    done
done
