#!/bin/sh 

dirs=". src tests"
pwd=`pwd`

if test -f Makefile ; then
    make clean
fi

for dir in $dirs
do
    if test -f $pwd/$dir/.cvsignore; then
	echo "Cleaning $pwd/$dir  ..."
	cd $pwd/$dir; rm -rf `cat .cvsignore`
    fi
done

cd $pwd/docs/examples
for dir in `ls | grep -v CVS` 
do
    if [ -d $dir ] ; then	
	cd $dir; make clean;cd ../
    fi
done