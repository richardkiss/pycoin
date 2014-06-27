#!/bin/sh

THIS_PATH=$0
if [ `expr $0 : '\/'` = 0 ]; then THIS_PATH="`pwd`/$THIS_PATH"; fi
THIS_DIR="`dirname $THIS_PATH`"
cd $THIS_DIR

PYTHONPATH=$THIS_DIR
export PYTHONPATH

tox
