#!/bin/sh
#
# list man pages found given one or more ??? passed in
#
# copied from
#  https://github.com/linux-nvme/libnvme:doc/list-man-pages.sh
#

for file do
    sed -n 's/ \* \([a-z_][a-z_0-9]*\)() -.*/\1/p' "$file"
    sed -n 's/ \* struct \([a-z_]*\) -.*/\1/p' "$file"
    sed -n 's/ \* enum \([a-z_]*\) -.*/\1/p' "$file"
done
