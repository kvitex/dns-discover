#!/bin/sh
export FLASK_APP=dns-discover.py
#export FLASK_ENV=development
/usr/bin/env python3 -m flask run --host=127.0.0.1 --port=9053
