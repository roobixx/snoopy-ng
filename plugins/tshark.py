#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import sys
import csv
import time
import subprocess
import StringIO
import threading
import logging
import wifi
import includes.monitor_mode as mm

from threading import Thread
from datetime import datetime
from Queue import Queue, Empty
from includes.common import snoop_hash, printFreq
from includes.prox import prox
from includes.mac_vendor import mac_vendor
from includes.fifoDict import fifoDict
from includes.fonts import *

class Snoop(Thread):
    """
    This plugin sniffs 802.11 (WiFi) probe requests and beacon frames using
    tshark.
    """

    """"""
    def __init__(self, **kwargs):
        self.sniffErrors = 0
        self.ready_status = False
        self.sniffing = False

        self.iface = kwargs.get("iface", None)
        self.enable_monitor_mode = kwargs.get("mon", "False")
        self.hash_macs = kwargs.get("hash", "False")
        self.pcap = kwargs.get("pcap")
        self.verb = kwargs.get("verbose", 1)
        self.subproc = None
        self.packet_q = None

        self.fname = os.path.splitext(os.path.basename(__file__))[0]
        self.proxWindow = kwargs.get('proxWindow', 300)
        self.probes_prox = prox(proxWindow=self.proxWindow, identName="mac", pulseName="num_probes", verb=0, callerName=self.fname)
        self.beacons_prox = prox(proxWindow=self.proxWindow, identName="mac", pulseName="num_beacons", verb=0, callerName=self.fname)

        self.device_vendor = fifoDict(names=("mac", "vendor", "vendorLong"))
        self.client_ssids = fifoDict(names=("mac", "ssid"))
        self.last_probes_update = 0
        self.last_beacons_update = 0
        self.probes_count = 0
        self.ap_names = fifoDict(names=("mac", "ssid"))
        self.mv = mac_vendor()

        self.enable_monitor_mode = False if self.enable_monitor_mode == "False" else True
        self.hash_macs = False if self.hash_macs == "False" else True

        Thread.__init__(self)
        self.setName('tshark')

    """"""
    @staticmethod
    def get_tables():
        tables = []
        for m in wifi.Snoop.get_modules():
            tbls = __import__(m, fromlist=['Snarf']).Snarf()
            tables.extend(tbls.get_tables())
        return tables

    """"""
    @staticmethod
    def get_parameter_list():
        info = {"info" : "This plugin sniffs 802.11 probe requests and beacon frames using tshark",
                "parameter_list" : [("iface=<dev>", "interface to listen on. e.g. -m tshark:iface=mon0"),
                                    ("mon=[True|False]","First enable monitor mode on <iface>. e.g. -m tshark:iface=mon0,mon=True. If no <iface> specified, will find first appropriate one.")
                                    ]
                }
        return info

    """"""
    def is_ready(self):
        return self.ready_status

    """"""
    def stop(self):
        self.sniffing = False
        if self.subproc is None:
            return
        self.subproc.kill()
        self.subproc = None

    """"""
    def run(self):
        shownMessage = False
        self.sniffing = True

        if self.enable_monitor_mode:
            self.iface = mm.enable_monitor_mode(self.iface)
            if not self.iface:
                if not shownMessage:
                    logging.error("No suitable monitor interface available. Will check every 5 seconds, but not display this message again.")
                    shownMessage = True
                time.sleep(5)
        if not self.iface and self.enable_monitor_mode:
            pass
        if not self.iface:
            logging.info("No interface specified. Will sniff *all* interfaces.")
        else:
            logging.info("Starting sniffing on interface '%s'"%self.iface)
        try:
            self.ready_status = True
            shownMessage = False
            self.ready_status = True
            self.sniff()
        except Exception, e:
            logging.error(("Exception caught whilst sniffing. "
                           "Will back off for 5 seconds, "
                           "and try restart '%s' plugin") % __name__)
            logging.error(e)
            self.sniffErrors += 1

        if self.sniffErrors > 3:
            logging.error("Restarting module '%s' after 5 failed attempts" %__file__)

        time.sleep(5)

    """"""
    def sniff(self):
        cmd_iface = "-i " + self.iface if self.iface is not None else ""
        cmd = [
            "tshark -l",
            cmd_iface,
            "-R 'wlan.fcs_good eq 1 and (wlan.fc.type_subtype eq 4 or wlan.fc.type_subtype eq 8)'",
            "-T fields -e wlan.fc.type_subtype -e wlan.sa -e wlan_mgt.ssid -e radiotap.dbm_antsignal -e frame.time -E separator=, -E quote=d"
        ]
        self.subproc = subprocess.Popen(" ".join(cmd), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, close_fds='posix' in sys.builtin_module_names)
        self.packet_q = Queue()
        t = threading.Thread(target=self.enqueue_output, args=(self.subproc.stdout, self.packet_q))
        t.daemon = True
        t.start()

    """"""
    def enqueue_output(self, out, queue):
        for line in iter(out.readline, b''):
            queue.put(line)
        out.close()

    """"""
    def parse(self, line):
        c = csv.reader(StringIO.StringIO(line), delimiter=",")
        r = next(iter(c), None)
        r.extend([0])
        d = datetime.strptime(r[4][:-3], "%b %d, %Y %H:%M:%S.%f")
        r[4] = d
        r[5] = d.microsecond
        return r

    """"""
    def proc_packet(self, p):
        if p is None:
            return

        frame_type = int(p[0], 16)
        mac = re.sub(':', '', p[1])
        ssid = p[2].decode('utf-8')
        sig_str = p[3]
        timeStamp = p[4]
        vendor = self.mv.lookup(mac[:6])

        if self.hash_macs is True:
            mac = snoop_hash(mac)

        self.device_vendor.add((mac, vendor[0], vendor[1]))

        if frame_type == 4:
            self.probes_prox.pulse(mac, timeStamp)
            if self.verb > 1 and len(ssid) > 0:
                logging.info("Plugin %s%s%s noted device %s%s%s (%s%s%s) probing for %s%s%s" % (GR,self.fname,G,GR,mac,G,GR,vendor[0],G,GR,ssid,G))
            if len(ssid) > 0:
                self.client_ssids.add((mac, ssid))
                self.probes_count += 1
        elif frame_type == 8:
            self.beacons_prox.pulse(mac, timeStamp)
            if self.verb > 1 and len(ssid) > 0:
                logging.info("Plugin %s%s%s noted Access Point %s%s%s (%s%s%s) beaconing for %s%s%s" % (GR,self.fname,G,GR,mac,G,GR,vendor[0],G,GR,ssid,G))
            if len(ssid) > 0:
                self.ap_names.add((mac, ssid))

    """"""
    def get_data(self):
        while True:
            try:
                line = self.packet_q.get_nowait()
            except Empty:
                break
            else:
                self.proc_packet(self.parse(line))

        probes_prox =  self.probes_prox.getProxs()
        beacons_prox =  self.beacons_prox.getProxs()

        device_vendors = self.device_vendor.getNew()
        client_ssids = self.client_ssids.getNew()
        ap_names = self.ap_names.getNew()
        os_time = os.times()[4]

        if self.verb > 0 and probes_prox and abs(os_time - self.last_probes_update) > printFreq:
            logging.info("Plugin %s%s%s currently observing %s%d%s client devices" % (GR,self.fname,G,GR,self.probes_prox.getNumProxs(),G))
            logging.info("Plugin %s%s%s has collected %s%d%s probe requests" % (GR,self.fname,G,GR,self.probes_count,G))
            self.last_probes_update = os_time

        if self.verb > 0 and beacons_prox and abs(os.times()[4] - self.last_beacons_update) > printFreq:
            logging.info("Plugin %s%s%s currently observing %s%d%s Access Points" % (GR,self.fname,G,GR,self.beacons_prox.getNumProxs(),G))
            self.last_beacons_update = os_time

        data = [("vendors", device_vendors),
                ("wifi_client_obs", probes_prox),
                ("wifi_client_ssids", client_ssids),
                ("wifi_AP_obs", beacons_prox),
                ("wifi_AP_ssids", ap_names)
        ]
        return data


if __name__ == "__main__":
    Snoop()

