#!/bin/sh
export FLASK_APP=dns-discover.py
#export FLASK_ENV=development
/usr/bin/env python3 -m flask run --host=$1 --port=$2
