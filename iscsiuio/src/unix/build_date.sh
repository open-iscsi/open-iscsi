#!/bin/bash
#
# build the build_date.c and build_date.h files
#
# (bash required for getopts)
#

THIS_CMD="build_date"

usage()
{
    echo "usage: $THIS_CMD -c OUTSRC -- generate date C code file OUTSRC"
    echo "   or: $THIS_CMD -i OUTHDR -- generate date C code include file OUTHDR"
}

generate_source_file()
{
    outfile="$1"
    if [ -n "$SOURCE_DATE_EPOCH" ] ; then
	echo 'char *build_date = "'`LC_ALL=C.UTF-8 date --date=@$SOURCE_DATE_EPOCH -u`'";' >"$outfile"
    else
	echo 'char *build_date = "'`date`'";' >"$outfile"
    fi
}

generate_include_file()
{
    outfile="$1"
    echo 'extern char *build_date;' >"$outfile"
}


while getopts :c:i:h opt; do
    case "$opt" in
    c) generate_source_file $OPTARG; exit 0 ;;
    i) generate_include_file $OPTARG; exit 0 ;;
    h) usage; exit 0 ;;
    ?) echo "unknown option: $opt" 1>&2; usage; exit 1 ;; 
    *) echo "huh???"
    esac
done
