
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
from xmlrpc.client import DateTime
import datetime


log = logging.getLogger(__name__)

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

class Xen:
    def __init__(self, host, user, password, verify_ssl=True):
        self._verify_ssl = verify_ssl
        self._user = user
        self._password = password
        self._host = host
        self.session = XenAPI.Session(f"https://{host}", ignore_ssl=not self._verify_ssl)
        self._retries = 0
        self._maxretries = 2
        self._timeout_retry = 30

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

    def getHostRRD(self, hostuuid: str) -> dict:
        # get full RRD
        qsdata = {
            "session_id": self.session_id,
            "json": "true"
        }
        return json.load(self.urlopenhost(hostuuid, "/host_rrd", qsdata))

    def getVmRRD(self, vmuuid: str) -> dict:
        vm = self.xenapi.VM.get_by_uuid(vmuuid)
        if vm == "OpaqueRef:NULL":
            raise KeyError(f"VM {vmuuid} invalid.")
        resident_on = self.xenapi.VM.get_resident_on(vm)
        if resident_on == "OpaqueRef:NULL":
            return {}
        hostuuid = self.xenapi.host.get_uuid(resident_on)
        qsdata = {
            "session_id": self.session_id,
            "uuid": vmuuid,
            "json": "true"
        }
        return json.load(self.urlopenhost(hostuuid, "/vm_rrd", qsdata))

    def getUpdatesRRD(self, hostuuid: str, cf: str = 'AVERAGE') -> dict:
        qsdata = {
            "session_id": self.session_id,
            "json": "true",
            "start": int(time.time()) - 10,
            "cf": cf,
            "host": "true"
        }
        return json.load(self.urlopenhost(hostuuid, "/rrd_updates", qsdata))

    def urlopenhost(self, hostuuid: str, path: str, qsdata: dict) -> dict:
        host = self.xenapi.host.get_by_uuid(hostuuid)
        host_interface = self.xenapi.host.get_management_interface(host)
        host_ip = self.xenapi.PIF.get_IP(host_interface)
        if host_ip is None:
            raise ValueError(f"Unable to get IP for host '{host}'")
        url=f"https://{host_ip}{path}?{urllib.parse.urlencode(qsdata)}"
        return self.urlopen(url)


    def urlopen(self, url: str) -> dict:
        kwargs = {}
        if self._retries > self._maxretries:
            raise Exception("Number of retries exceded. Something is wrong.")
        if not self._verify_ssl:
            kwargs['context'] = ssl._create_unverified_context()
        try:
            res=urllib.request.urlopen(url, **kwargs)
            self._retries = 0
            return res
        except urllib.error.HTTPError as e:
            self._retries += 1
            if e.status == 401:
                self.login()
                return self.urlopen(url)
            raise
        except urllib.error.URLError as e:
            self._retries += 1
            log.exception(e)
            time.sleep(self._timeout_retry)
            return self.urlopen(url)
        except Exception as e:
            log.exception(e)
            log.error(f"Unknown error {str(e)}")
            raise


    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.xenapi.session.logout()

class _SammPromHandler(_SilentHandler):
    def log_message(self, format, *args):
        message = format % args
        log.info("%s %s", self.address_string(), message)

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


class SammXenExporter:
    def __init__(self, xen_host=None, xen_user=None, xen_password=None, verify_ssl=None, port=None, poll_time=None, loglevel=None):
        self.xen_host = xen_host
        if xen_host is None:
            self.xen_host = os.getenv("XEN_HOST", "localhost")

        self.xen_user = xen_user
        if xen_user is None:
            self.xen_user = os.getenv("XEN_USER", "root")

        self.xen_password = xen_password
        if xen_password is None:
            self.xen_password = os.getenv("XEN_PASSWORD", "")

        self.verify_ssl = verify_ssl
        if verify_ssl is None:
            self.verify_ssl = True if os.getenv("XEN_SSL_VERIFY", "true") == "true" else False


        try:
            if loglevel is None:
                log.setLevel(os.getenv("XEN_LOGLEVEL", "INFO"))
            else:
                log.setLevel(loglevel)
        except ValueError:
            log.setLevel('INFO')
            log.warning(f"Invalid loglevel defined in XEN_LOGLEVEL={self.loglevel}")

        try:
            if isinstance(port, int):
                self.port = port
            elif isinstance(port, str):
                self.port = int(port, 10)
            else:
                self.port = os.getenv("XEN_COLPORT", '8000')
                self.port = int(self.port, 10)
        except ValueError:
            log.warning(f"Invalid port defined in XEN_COLPORT={port} variable. Assuming default 8000")
            port = 8000

        try:
            if isinstance(poll_time, int):
                self.poll_time = poll_time
            elif isinstance(poll_time, str):
                self.poll_time = int(poll_time, 10)
            else:
                self.poll_time = os.getenv("XEN_POLLTIME", '60')
                self.poll_time = int(self.poll_time, 10)
        except ValueError:
            log.warning(f"Invalid poll time defined in XEN_POLLTIME={poll_time}. Assuming default 60")
            poll_time = 60

        self.info_labels = {}
        self.static_metrics = {}
        self.extra_metric_labels = {}

        self.all_metrics = {}
        # all_metrics structure
        #{
        #    "(metric_name string)": { (instrument Gauge, Counter or other)}
        #}


        # Will store all metrics specific to labels
        self.all_info_metrics = {}
        self.all_data = {}
        # all_data structure
        #{
        #   "pool_uuid": "(string)",
        #   "vm_guest_metrics": {
        #      "(uuid string)": { (class VM_guest_metrics) }
        #   },
        #   "sr": {
        #      "(uuid string)": { (class SR) }
        #   },
        #   "vm": {
        #      "(uuid string)": { (class VM) }
        #   },
        #   "pool": {
        #      "(uuid string)": { (class pool) }
        #   },
        #   "host": {
        #      "(uuid string)": { (class host) }
        #   }
        #}

        self.proctime = Counter("samm_process_time", "SAMM Xen exporter process time in seconds", ["xen_host"])
        self.proctime_rrd = Gauge("samm_process_time_pullrrd", "SAMM process time collecting RRD data", ["uuid", "name_label"])
        self.proctime_updatehostmetrics = Gauge("samm_process_time_updatehostmetrics", "SAMM process time updating metrics", ["uuid", "name_label"])
        self.x = Xen(self.xen_host, self.xen_user, self.xen_password, self.verify_ssl)

    def update_host_metrics(self, legends, values):
        for i in range(len(legends)):
            legend = legends[i]
            value = values[i]
            metric_name, labels, label_values, collector_type = legend_to_metric(legend)
            labels += self.extra_metric_labels.get(collector_type, [])
            uuid = label_values[0]
            label_values += [ self.all_data[collector_type].get(uuid, {}).get(prop, '-1') for prop in self.extra_metric_labels[collector_type] ]
            m = self.all_metrics.get(metric_name)
            if m is None:
                m = self.all_metrics[metric_name] = Gauge(metric_name, metric_name, labels)
            m.labels(*label_values).set(value)

    def update_info(self, collector_data, collector_type):
        metric_name = "xen_" + collector_type + "_info"
        label_values = []
        for k, v in self.info_labels[collector_type].items():
            label_values.append(recget(collector_data, v, "none"))
        if collector_data['uuid'] in self.all_info_metrics:
            old_metric = self.all_info_metrics[collector_data['uuid']]

        if metric_name not in self.all_metrics:
            raise KeyError(f"Metric {metric_name} not defined in all_metrics")
        m = self.all_metrics[metric_name]

        # remove old info for labels
        if collector_data['uuid'] in self.all_info_metrics:
            old = self.all_info_metrics.pop(collector_data['uuid'])
            m.remove(*old._labelvalues)

        self.all_info_metrics[collector_data['uuid']] = m.labels(*label_values)
        self.all_info_metrics[collector_data['uuid']].set(1.0)

    def update_static_metrics(self, collector_data, collector_type):
        for name, k in self.static_metrics.get(collector_type, {}).items():
            metric_name = "xen_" + collector_type + "_" + name
            m = self.all_metrics.get(metric_name)
            if m is None:
                m = self.all_metrics[metric_name] = Gauge(metric_name, metric_name, [ 'uuid' ])
            try:
                val = recget(collector_data, k, -1)
                if isinstance(val, DateTime):
                    try:
                        data = datetime.datetime.strptime(val.value, "%Y%m%dT%H:%M:%SZ").timestamp() * 1000
                    except ValueError:
                        log.error(f"Invalid value at metric={metric_name} tags={collector_data}: datetime {val}")
                        data = -2
                else:
                    data = float(val)
            except Exception as e:
                log.error(f"Invalid value at metric={metric_name} tags={collector_data}: {str(e)}")
                data = float(-3)
            m.labels(collector_data['uuid']).set(data)


    def customize_sr(self, srdata: dict):
        srdata['sr_uuid'] = srdata['uuid'].split('-')[0]

    def customize_vm(self, vmdata: dict):
        # TODO: generalize the function that resolves references
        # resolve reference
        if vmdata['resident_on'] == 'OpaqueRef:NULL':
            vmdata['resident_on'] = ''
        else:
            vmdata['resident_on'] = self.x.xenapi.host.get_record(vmdata['resident_on']).get('uuid', 'none')

        if vmdata['guest_metrics'] != "OpaqueRef:NULL":
            guest_metrics = self.x.xenapi.VM_guest_metrics.get_record(vmdata['guest_metrics'])
            self.all_data.setdefault('vm_guest_metrics', {})[guest_metrics['uuid']] = guest_metrics
            self.update_info(guest_metrics, 'vm_guest_metrics')
            vmdata['guest_metrics'] = guest_metrics['uuid']
        else:
            vmdata['guest_metrics'] = ''

    def customize_host(self, hdata: dict):
        hdata['pool_uuid'] = self.all_data['pool_uuid']
        start = time.process_time()
        try:
            updates=self.x.getUpdatesRRD(hdata['uuid'])
        except Exception as e:
            # TODO: Something went wrong and no data was generated. Need to create
            #       a metric that will inform the graphical interface that this 
            #       exporter need to be reviewed
            log.exception(e)
            return
        self.proctime_rrd.labels(hdata['uuid'], hdata['name_label']).set(time.process_time() - start)

        # update metrics
        start = time.process_time()
        self.update_host_metrics(updates['meta']['legend'], updates['data'][0]['values'])
        self.proctime_updatehostmetrics.labels(hdata['uuid'], hdata['name_label']).set(time.process_time() - start)

    def customize_pool(self, pdata: dict):
        pdata['master'] = self.x.xenapi.host.get_record(pdata['master']).get('uuid')
        self.all_data['pool_uuid'] = pdata['uuid']

    def update_objects(self, collector_type: str):
        ctx = getattr(self.x.xenapi, collector_type)
        for o in ctx.get_all():
            try:
                data = ctx.get_record(o)
            except Exception as e:
                log.exception(e)
                continue
            self.all_data.setdefault(collector_type.lower(), {})[data['uuid']] = data

            customize_func = getattr(self, "customize_" + collector_type.lower(), lambda x: None)
            customize_func(data)
            self.update_info(data, collector_type.lower())
            self.update_static_metrics(data, collector_type.lower())


    def run(self):
        server, _ = start_http_server(self.port)
        server.RequestHandlerClass = _SammPromHandler
        log.info(f"Started exporter server on port {self.port}")
        with self.x:
            while True:
                self.update_objects('pool')
                self.update_objects('SR')
                self.update_objects('VM')
                self.update_objects('host')
                pt = time.process_time()
                self.proctime.labels(self.xen_host).reset()
                self.proctime.labels(self.xen_host).inc(pt)
                log.info(f"Finished collecting data from xenserver. ({pt})")
                time.sleep(self.poll_time)

    def load_config(self, config_file):

        with open(config_file, "r") as f:
            self.config = json.load(f)
            self.info_labels = self.config['info_labels']
            self.static_metrics = self.config['static_metrics']
            self.extra_metric_labels = self.config['extra_metric_labels']

        self.all_metrics["xen_host_info"] = Gauge("xen_host_info", "Information about the XenServer Host", list(self.info_labels.get('host', {}).keys()))
        self.all_metrics["xen_vm_info"] = Gauge("xen_vm_info", "Information about Virtual Machines", list(self.info_labels.get('vm', {}).keys()))
        self.all_metrics["xen_vm_guest_metrics_info"] = Gauge("xen_vm_guest_metrics_info", "Information about guest metrics", list(self.info_labels.get('vm_guest_metrics', {}).keys()))
        self.all_metrics["xen_sr_info"] = Gauge("xen_sr_info", "Information about Storage Repositories", list(self.info_labels.get('sr', {}).keys()))
        self.all_metrics["xen_pool_info"] = Gauge("xen_pool_info", "Information about the XenServer Pool", list(self.info_labels.get('pool', {}).keys()))

