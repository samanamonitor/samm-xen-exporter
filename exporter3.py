import os
from exporter2 import Xen
from prometheus_client import Gauge, start_http_server
import time

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

info_labels = {
      "vm": [
            "uuid",
            "name_label",
            "resident_on",
            "power_state"
      ],
      "VM_guest_metrics": [
            "uuid",
            "os_version.distro",
            "os_version.major",
            "os_version.minor",
            "os_version.build",
            "netbios_name.host_name",
            "PV_drivers_version.major",
            "PV_drivers_version.minor",
            "PV_drivers_version.micro",
            "PV_drivers_version.build",
      ],
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
host_info = Gauge("xen_host_info", "Information about the XenServer Host", list(info_labels['host'].keys()))
all_host_info = {}

def recget(d, key, default=None):
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
    return "xen_" + collector_type + "_" + metric_name, labels, label_values

def update_metrics(legends, values):
    for i in range(len(legends)):
        legend = legends[i]
        value = values[i]
        metric_name, labels, label_values = legend_to_metric(legend)
        m = all_metrics.get(metric_name)
        if m is None:
            m = all_metrics[metric_name] = Gauge(metric_name, metric_name, labels)
        m.labels(*label_values).set(value)

def update_host_info(hdata):
    label_values = []
    for k, v in info_labels['host'].items():
        label_values.append(recget(hdata, v, "none"))
    if host in all_host_info:
        old = all_host_info.pop(host)
        host_info.remove(*old._labelvalues)
    all_host_info[host] = host_info.labels(*label_values)
    all_host_info[host].set(1.0)

def main(xen_host, xen_user, xen_password, verify_ssl):
    start_http_server(8000)
    with Xen(xen_host, xen_user, xen_password, verify_ssl) as x:
        while True:
            xenhosts=x.xenapi.host.get_all()
            for hx in xenhosts:
                hdata = x.xenapi.host.get_record(hx)
                update_host_info(hdata)
                updates=x.getUpdatesRRD(hx)
                update_metrics(updates['meta']['legend'], updates['data'][0]['values'])
            time.sleep(60)

def load_env():
    xen_user = os.getenv("XEN_USER", "root")
    xen_password = os.getenv("XEN_PASSWORD", "")
    xen_host = os.getenv("XEN_HOST", "localhost")
    xen_mode = os.getenv("XEN_MODE", "host")
    verify_ssl = True if os.getenv("XEN_SSL_VERIFY", "true") == "true" else False
    return xen_user, xen_password, xen_host, verify_ssl

if __name__ == "__main__":
    main(*loadenv())

