import os
from exporter2 import Xen
from prometheus_client import Gauge, start_http_server
import time

xen_password = os.getenv("XEN_PASSWORD", "")
xen_user = os.getenv("XEN_USER", "root")
xen_host = os.getenv("XEN_HOST", "localhost")
xen_mode = os.getenv("XEN_MODE", "host")
verify_ssl = True if os.getenv("XEN_SSL_VERIFY", "true") == "true" else False

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

x=Xen(xen_host, xen_user, xen_password, verify_ssl)
start_http_server(8000)
all_metrics = {}
xenhosts=x.xenapi.host.get_all()

while True:
    for hx in xenhosts:
        updates=x.getUpdatesRRD(hx)
        update_metrics(updates['meta']['legend'], updates['data'][0]['values'])
    time.sleep(60)
