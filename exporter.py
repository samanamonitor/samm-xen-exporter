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

xe = None

class Xen:
    def __init__(self, host, user, password, verify_ssl=True, login=True):
        self._verify_ssl = verify_ssl
        self._user = user
        self._password = password
        self._host = host
        self.session = XenAPI.Session(f"https://{host}", ignore_ssl=not self._verify_ssl)
        if login:
            self.login()

    def login(self):
        try:
            self.session.xenapi.login_with_password(self._user, self._password)
        except XenAPI.XenAPI.Failure as e:
            d = eval(str(e))
            if len(d) == 2:
                if d[0] == 'HOST_IS_SLAVE':
                    self._host = d[1]
                    print(f"WARNING: This host is slave. Connecting to '{self._host}'")
                    self.session = XenAPI.Session(f"https://{d[1]}", ignore_ssl=not self._verify_ssl)
                    self.session.xenapi.login_with_password(self._user, self._password)
            else:
                raise
        log.info(f"Logged in to Xen {self._host} with username {self._user}.")

    @property
    def session_id(self):
        return self.session._session

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

    def getUpdatesRRD(self, hdata, cf='AVERAGE'):
        host = self.xenapi.host.get_by_uuid(hdata['uuid'])
        kwargs = {}
        if not self._verify_ssl:
            kwargs['context'] = ssl._create_unverified_context()
        host_ip = self.xenapi.PIF.get_record(self.xenapi.host.get_management_interface(host)).get('IP')
        if host_ip is None:
            raise ValueError(f"Unable to get IP for host '{host}'")
        qsdata = {
            "session_id": self.session_id,
            "json": "true",
            "start": int(time.time()) - 10,
            "cf": cf,
            "host": "true"
        }
        res=urllib.request.urlopen(f"https://{host_ip}/rrd_updates?{urllib.parse.urlencode(qsdata)}", **kwargs)
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

info_labels = {}
static_metrics = {}
extra_metric_labels = {}

all_metrics = {}
# Will store all metrics specific to labels
all_info_metrics = {}
all_data = {}

proctime = Counter("samm_process_time", "SAMM Xen exporter process time in seconds", ["xen_host"])
proctime_rrd = Gauge("samm_process_time_pullrrd", "SAMM process time collecting RRD data", ["uuid", "name_label"])
proctime_updatehostmetrics = Gauge("samm_process_time_updatehostmetrics", "SAMM process time updating metrics", ["uuid", "name_label"])

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
    for i in range(len(legends)):
        legend = legends[i]
        value = values[i]
        metric_name, labels, label_values, collector_type = legend_to_metric(legend)
        labels += extra_metric_labels.get(collector_type, [])
        uuid = label_values[0]
        label_values += [ all_data[collector_type][uuid][prop] for prop in extra_metric_labels[collector_type] ]
        m = all_metrics.get(metric_name)
        if m is None:
            m = all_metrics[metric_name] = Gauge(metric_name, metric_name, labels)
        m.labels(*label_values).set(value)

def update_info(collector_data, collector_type):
    metric_name = "xen_" + collector_type + "_info"
    label_values = []
    for k, v in info_labels[collector_type].items():
        label_values.append(recget(collector_data, v, "none"))
    if collector_data['uuid'] in all_info_metrics:
        old_metric = all_info_metrics[collector_data['uuid']]

    if metric_name not in all_metrics:
        raise KeyError(f"Metric {metric_name} not defined in all_metrics")
    m = all_metrics[metric_name]

    # remove old info for labels
    if collector_data['uuid'] in all_info_metrics:
        old = all_info_metrics.pop(collector_data['uuid'])
        m.remove(*old._labelvalues)

    all_info_metrics[collector_data['uuid']] = m.labels(*label_values)
    all_info_metrics[collector_data['uuid']].set(1.0)

def update_static_metrics(collector_data, collector_type):
    for name, k in static_metrics.get(collector_type, {}).items():
        metric_name = "xen_" + collector_type + "_" + name
        m = all_metrics.get(metric_name)
        if m is None:
            m = all_metrics[metric_name] = Gauge(metric_name, metric_name, [ 'uuid' ])
        try:
            data = float(recget(collector_data, k, -1))
        except Exception:
            data = float(-1)
        m.labels(collector_data['uuid']).set(data)


def customize_sr(x, srdata):
    srdata['sr_uuid'] = srdata['uuid'].split('-')[0]

def customize_vm(x, vmdata):
    # TODO: generalize the function that resolves references
    # resolve reference
    if vmdata['resident_on'] == 'OpaqueRef:NULL':
        vmdata['resident_on'] = ''
    else:
        vmdata['resident_on'] = x.xenapi.host.get_record(vmdata['resident_on']).get('uuid', 'none')

    if vmdata['guest_metrics'] != "OpaqueRef:NULL":
        guest_metrics = x.xenapi.VM_guest_metrics.get_record(vmdata['guest_metrics'])
        all_data.setdefault('vm_guest_metrics', {})[guest_metrics['uuid']] = guest_metrics
        update_info(guest_metrics, 'vm_guest_metrics')

def customize_host(x, hdata):
    hdata['pool_uuid'] = all_data['pool_uuid']
    start = time.process_time()
    updates=x.getUpdatesRRD(hdata)
    proctime_rrd.labels(hdata['uuid'], hdata['name_label']).set(time.process_time() - start)

    # update metrics
    start = time.process_time()
    update_host_metrics(updates['meta']['legend'], updates['data'][0]['values'])
    proctime_updatehostmetrics.labels(hdata['uuid'], hdata['name_label']).set(time.process_time() - start)

def customize_pool(x, pdata):
    pdata['master'] = x.xenapi.host.get_record(pdata['master']).get('uuid')
    all_data['pool_uuid'] = pdata['uuid']

def update_objects(x, collector_type):
    ctx = getattr(x.xenapi, collector_type)
    for o in ctx.get_all():
        data = ctx.get_record(o)
        all_data.setdefault(collector_type.lower(), {})[data['uuid']] = data

        customize_func = globals().get("customize_" + collector_type.lower(), lambda x, y: None)
        customize_func(x, data)
        update_info(data, collector_type.lower())
        update_static_metrics(data, collector_type.lower())


def main(xen_host, xen_user, xen_password, verify_ssl=True, port=8000, poll_time=60):
    global xe
    server, _ = start_http_server(port)
    server.RequestHandlerClass = _SammPromHandler
    log.info(f"Started exporter server on port {port}")
    with Xen(xen_host, xen_user, xen_password, verify_ssl) as x:
        xe = x
        while True:
            update_objects(x, 'SR')
            update_objects(x, 'VM')
            update_objects(x, 'pool')
            update_objects(x, 'host')
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

def load_config(config_file):
    global info_labels
    global static_metrics
    global extra_metric_labels

    with open(config_file, "r") as f:
        config = json.load(f)
        info_labels = config['info_labels']
        static_metrics = config['static_metrics']
        extra_metric_labels = config['extra_metric_labels']

    all_metrics["xen_host_info"] = Gauge("xen_host_info", "Information about the XenServer Host", list(info_labels.get('host', {}).keys()))
    all_metrics["xen_vm_info"] = Gauge("xen_vm_info", "Information about Virtual Machines", list(info_labels.get('vm', {}).keys()))
    all_metrics["xen_vm_guest_metrics_info"] = Gauge("xen_vm_guest_metrics_info", "Information about guest metrics", list(info_labels.get('vm_guest_metrics', {}).keys()))
    all_metrics["xen_sr_info"] = Gauge("xen_sr_info", "Information about Storage Repositories", list(info_labels.get('sr', {}).keys()))
    all_metrics["xen_pool_info"] = Gauge("xen_pool_info", "Information about the XenServer Pool", list(info_labels.get('pool', {}).keys()))


if __name__ == "__main__":
    FORMAT = '%(asctime)s - %(levelname)s:%(funcName)s %(message)s'
    logging.basicConfig(stream=sys.stderr, format=FORMAT)
    config_file = 'config.json'
    if len(sys.argv) > 1:
        config_file = sys.argv[1]
    load_config(config_file)
    main(*load_env())

