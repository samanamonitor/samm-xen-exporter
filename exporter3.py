import sys
import os
from prometheus_client import Counter, Gauge, start_http_server
from prometheus_client.exposition import _SilentHandler
import time
import XenAPI
import urllib.request
import ssl
import json
import logging

log = logging.getLogger(__name__)

class Xen:
      def __init__(self, host, user, password, verify_ssl=True):
            self._verify_ssl = verify_ssl
            self.session = XenAPI.Session(f"https://{host}", ignore_ssl=not verify_ssl)
            try:
                  self.session.xenapi.login_with_password(user, password)
            except XenAPI.XenAPI.Failure as e:
                  d = eval(str(e))
                  if len(d) == 2:
                        if d[0] == 'HOST_IS_SLAVE':
                              print(f"WARNING: This host is slave. Connecting to '{d[1]}'")
                              self.session = XenAPI.Session(f"https://{d[1]}", ignore_ssl=not verify_ssl)
                              self.session.xenapi.login_with_password(user, password)
                  else:
                        raise
            self.session_id = self.session._session
            log.info(f"Logged in to Xen {host} with username {user}.")

      @property
      def xenapi(self):
            return self.session.xenapi

      def getHostRRD(self, host):
            # get full RRD
            kwargs = {}
            if not self._verify_ssl:
                  kwargs['context'] = ssl._create_unverified_context()
            host_ip = self.xenapi.PIF.get_record(self.xenapi.host.get_management_interface(host)).get('IP')
            if host_ip is None:
                  raise ValueError(f"Unable to get IP for host '{host}'")
            res=urllib.request.urlopen(f"https://{host_ip}/host_rrd?session_id={self.session_id}&json=true", **kwargs)
            return json.load(res)

      def getVmRRD(self, host, vm):
            #xen.xenapi.host.get_resident_VMs(xen.xenapi.host.get_all()[0])[0])['uuid']
            kwargs = {}
            if not self._verify_ssl:
                  kwargs['context'] = ssl._create_unverified_context()
            vmuuid=self.xenapi.VM.get_record(vm).get('uuid')
            if vmuuid is None:
                  raise ValueError(f"VM '{vm}' could not be found")
            host_ip = self.xenapi.PIF.get_record(self.xenapi.host.get_management_interface(host)).get('IP')
            if host_ip is None:
                  raise ValueError(f"Unable to get IP for host '{host}'")
            res=urllib.request.urlopen(f"https://{host_ip}/vm_rrd?session_id={self.session_id}&uuid={vmuuid}&json=true", **kwargs)
            return json.load(res)

      def getUpdatesRRD(self, host, cf='AVERAGE'):
            kwargs = {}
            if not self._verify_ssl:
                  kwargs['context'] = ssl._create_unverified_context()
            host_ip = self.xenapi.PIF.get_record(self.xenapi.host.get_management_interface(host)).get('IP')
            if host_ip is None:
                  raise ValueError(f"Unable to get IP for host '{host}'")
            start = int(time.time()) - 10
            res=urllib.request.urlopen(f"https://{host_ip}/rrd_updates?session_id={self.session_id}&json=true&start={start}&cf={cf}&host=true", **kwargs)
            return json.load(res)

      def __enter__(self):
            return self

      def __exit__(self, exc_type, exc_value, traceback):
            self.xenapi.session.logout()

class _SammPromHandler(_SilentHandler):
    def log_message(self, format, *args):
        message = format % args
        log.info("%s %s", self.address_string(), message)

sr_metric_names = [
    "avgqu",
    "inflight",
    "io",
    "iops",
    "iowait",
    "latency",
    "read",
    "write"
]
extra_labels = {
    "host": [ "name_label" ],
    "vm": [ "name_label" ]
}

info_labels = {
    "vm": {
        "uuid": "uuid",
        "name_label": "name_label",
        "power_state": "power_state",
        "resident_on": "resident_on"
    },
    "vm_guest_metrics": {
        "uuid": "uuid",
        "os_version_distro": "os_version.distro",
        "os_version_major": "os_version.major",
        "os_version_minor": "os_version.minor",
        "os_version_build": "os_version.build",
        "netbios_name": "netbios_name.host_name",
        "PV_drivers_version_major": "PV_drivers_version.major",
        "PV_drivers_version_minor": "PV_drivers_version.minor",
        "PV_drivers_version_micro": "PV_drivers_version.micro",
        "PV_drivers_version_build": "PV_drivers_version.build"
    },
    "host": {
        "uuid": "uuid",
        "name_label": "name_label",
        "API_version_major": "API_version_major",
        "API_version_minor": "API_version_minor",
        "API_version_vendor": "API_version_vendor",
        "product_version": "software_version.product_version",
        "platform_name": "software_version.platform_name",
        "platform_version": "software_version.platform_version",
        "xapi_version": "software_version.xapi",
        "xapi_build": "software_version.xapi_build",
        "xen_version": "software_version.xen",
        "linux_version": "software_version.linux",
        "network_backend": "software_version.network_backend",
        "db_schema": "software_version.db_schema",
        "cpu_count": "cpu_info.cpu_count",
        "socket_count": "cpu_info.socket_count",
        "threads_per_core": "cpu_info.threads_per_core",
        "cpu_vendor": "cpu_info.vendor",
        "cpu_speed": "cpu_info.speed",
        "cpu_modelname": "cpu_info.modelname",
        "multipathing": "other_config.multipathing",
        "mpath_boot": "other_config.mpath_boot",
        "hostname": "hostname",
        "address": "address",
        "bios_vendor": "bios_strings.bios-vendor",
        "bios_version": "bios_strings.bios-version",
        "system_manufacturer": "bios_strings.system-manufacturer",
        "system_product_name": "bios_strings.system-product-name",
        "system_serial_number": "bios_strings.system-serial-number"
    }
}

all_metrics = {}
all_info = {
    "host": Gauge("xen_host_info", "Information about the XenServer Host", list(info_labels['host'].keys())),
    "vm": Gauge("xen_vm_info", "Information about Virtual Machines", list(info_labels['vm'].keys())),
    "vm_guest": Gauge("xen_vm_guest_info", "Information about guest metrics", list(info_labels['vm_guest_metrics'].keys()))
}
# Will store all metrics specific to labels
all_info_metrics = {
    "host": {},
    "vm": {}
}
proctime = Counter("samm_process_time", "SAMM Xen exporter process time in seconds", ["xen_host"])
proctime_rrd = Gauge("samm_process_time_pullrrd", "SAMM process time collecting RRD data", ["uuid", "name_label"])
proctime_updatehostmetrics = Gauge("samm_process_time_updatehostmetrics", "SAMM process time updating metrics", ["uuid", "name_label"])
all_vm_data = {}
all_host_data = {}

def recget(d, key, default=None):
    if not isinstance(d, dict):
        return default
    keys = key.split(".")
    v = d
    for k in keys:
        if k not in v:
            return default
        v = v.get(k)
    return v

def legend_to_metric(legend):
    data = legend.split(':')
    collector_type = data[1]
    collector = data[2]
    metric_name = data[3].lower().replace('-', '_')
    data2 = metric_name.split('_')
    labels = [ "uuid" ]
    label_values = [ collector ]
    if data2[0] == 'vbd':
        labels.append("device")
        label_values.append(data2.pop(1))
        metric_name = '_'.join(data2)
    elif data2[0] == 'vif':
        labels.append("device")
        label_values.append(data2.pop(1))
        metric_name = '_'.join(data2)
    elif data2[0] == 'pif':
        labels.append('device')
        label_values.append(data2.pop(1))
        metric_name = '_'.join(data2)
    elif data2[0] in sr_metric_names:
        metric_name, _, sruuid = metric_name.rpartition('_')
        labels.append('sr_uuid')
        label_values.append(sruuid)
        metric_name = "sr_" + metric_name
    elif data2[0] == 'cpu':
        metric_name = '_'.join(data2)
    elif data2[0][:3] == 'cpu':
        labels.append('index')
        labels.append('state')
        index = data2[0][3:]
        if len(data2) > 1 and (data2[1][0] == 'p' or data2[1][0] == 'c'):
            state = data2.pop(1)
        else:
            state = ''
        label_values.append(index)
        label_values.append(state)
        metric_name = 'cpu'
    metric_name = metric_name.replace('-', '_')
    return "xen_" + collector_type + "_" + metric_name, labels, label_values, collector_type

def update_host_metrics(legends, values):
#    if len(extra_labels) != len(extra_values):
#        raise ValueError(f"Invalid extra labels. Number of extra_labels({extra_labels}) must be equal to extra_values({extra_values})")
    for i in range(len(legends)):
        legend = legends[i]
        value = values[i]
        metric_name, labels, label_values, collector_type = legend_to_metric(legend)
        labels += extra_labels.get(collector_type, [])
        uuid = label_values[0]
        if collector_type == 'host':
            label_values += [ all_host_data[uuid][prop] for prop in extra_labels[collector_type] ]
        elif collector_type == 'vm':
            label_values += [ all_vm_data[uuid][prop] for prop in extra_labels[collector_type] ]
        m = all_metrics.get(metric_name)
        if m is None:
            m = all_metrics[metric_name] = Gauge(metric_name, metric_name, labels)
        m.labels(*label_values).set(value)

def update_info(collector_data, collector_type):
    label_values = []
    for k, v in info_labels[collector_type].items():
        label_values.append(recget(collector_data, v, "none"))
    if collector_data['uuid'] in all_info_metrics:
        old_metric = all_info_metrics[collector_data['uuid']]

    if collector_type not in all_info:
        raise KeyError(f"Collector type {collector_type} not defined in all_info")

    # remove old info for labels
    if collector_data['uuid'] in all_info_metrics:
        old = all_info_metrics.pop(collector_data['uuid'])
        all_info[collector_type].remove(*old._labelvalues)

    all_info_metrics[collector_data['uuid']] = all_info[collector_type].labels(*label_values)
    all_info_metrics[collector_data['uuid']].set(1.0)

def poll(x, xen_host):
    xenhosts=x.xenapi.host.get_all()
    for hx in xenhosts:
        hdata = x.xenapi.host.get_record(hx)
        all_host_data[hdata['uuid']] = hdata
        update_info(hdata, 'host')
        vms = x.xenapi.host.get_resident_VMs(hx)
        for v in vms:
            temp = x.xenapi.VM.get_record(v)
            all_vm_data[temp['uuid']] = temp
            # resolve reference
            temp['resident_on'] = x.xenapi.host.get_record(temp['resident_on']).get('uuid', 'none')
            update_info(temp, 'vm')
        start = time.process_time()
        updates=x.getUpdatesRRD(hx)
        proctime_rrd.labels(hdata['uuid'], hdata['name_label']).set(time.process_time() - start)
        start = time.process_time()
        update_host_metrics(updates['meta']['legend'], updates['data'][0]['values'])
        proctime_updatehostmetrics.labels(hdata['uuid'], hdata['name_label']).set(time.process_time() - start)

def main(xen_host, xen_user, xen_password, verify_ssl=True, port=8000, poll_time=60):
    server, _ = start_http_server(port)
    server.RequestHandlerClass = _SammPromHandler
    log.info(f"Started exporter server on port {port}")
    with Xen(xen_host, xen_user, xen_password, verify_ssl) as x:
        while True:
            poll(x, xen_host)
            pt = time.process_time()
            proctime.labels(xen_host).reset()
            proctime.labels(xen_host).inc(pt)
            log.info(f"Finished collecting data from xenserver. ({pt})")
            time.sleep(poll_time)

def load_env():
    xen_host = os.getenv("XEN_HOST", "localhost")
    xen_user = os.getenv("XEN_USER", "root")
    xen_password = os.getenv("XEN_PASSWORD", "")
    verify_ssl = True if os.getenv("XEN_SSL_VERIFY", "true") == "true" else False
    loglevel = os.getenv("XEN_LOGLEVEL", "INFO")
    port = os.getenv("XEN_COLPORT", '8000')
    poll_time = os.getenv("XEN_POLLTIME", '60')

    try:
        log.setLevel(loglevel)
    except ValueError:
        log.setLevel('INFO')
        log.warning(f"Invalid loglevel defined in XEN_LOGLEVEL={loglevel}")

    try:
        port = int(port, 10)
    except ValueError:
        log.warning(f"Invalid port defined in XEN_COLPORT={port} variable. Assuming default 8000")
        port = 8000

    try:
        poll_time = int(poll_time, 10)
    except ValueError:
        log.warning(f"Invalid poll time defined in XEN_POLLTIME={poll_time}. Assuming default 60")
        poll_time = 60

    return xen_host, xen_user, xen_password, verify_ssl, port, poll_time

if __name__ == "__main__":
    FORMAT = '%(asctime)s - %(levelname)s:%(funcName)s %(message)s'
    logging.basicConfig(stream=sys.stderr, format=FORMAT)
    main(*load_env())

