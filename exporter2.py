#!/usr/bin/python3

import XenAPI
import urllib.request
import ssl
import json
import time

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
      "host": [
            "uuid",
            "name_label",
            "API_version_major",
            "API_version_minor",
            "API_version_vendor",
            "software_version.product_version",
            "software_version.platform_name",
            "software_version.platform_version",
            "software_version.xapi",
            "software_version.xapi_build",
            "software_version.xen",
            "software_version.linux",
            "software_version.network_backend",
            "software_version.db_schema",
            "cpu_info.cpu_count",
            "cpu_info.socket_count",
            "cpu_info.threads_per_core",
            "cpu_info.vendor",
            "cpu_info.speed",
            "cpu_info.modelname",
            "other_config.multipathing",
            "other_config.mpath_boot",
            "hostname",
            "address",
            "bios_strings.bios-vendor",
            "bios_strings.bios-version",
            "bios_strings.system-manufacturer",
            "bios_strings.system-product-name",
            "bios_strings.system-serial-number",
      ]
}

static_metrics = {
      "vm": [
            "memory_overhead",
            "memory_target",
            "memory_static_max",
            "memory_dybamic_max",
            "memory_dynamic_min",
            "memory_static_min",
            "VCPUs_at_startup",
            "metrics"
      ],
      "VM_metrics": [
            "memory_actual",
            "VCPUs_number",
            "start_time",
            "install_time"
      ],
      "host": [
            "other_config.agent_start_time",
            "other_config.boot_time"
            "last_software_update"
      ],
      "host_metrics": [
            "memory_total",
            "memory_free",
            "last_updated"
      ]
}


#allvms = x.xenapi.VM.get_all()

#xenhosts=xen.xenapi.host.get_all()
#list = []
#for host in xenhosts:
#      list.append(xen.xenapi.PIF.get_record(xen.xenapi.host.get_management_interface(host))['IP'])

# VM full RRD
#res=urllib.request.urlopen(f"https://{exporter.xen_host}/vm_rrd?session_id={xen._session}&uuid={vmuuid}&json=true", context=ssl._create_unverified_context())

# get only updates
#res=urllib.request.urlopen(f"https://{exporter.xen_host}/rrd_updates?session_id={xen._session}&json=true&start={int(time.time()) - 10}&cf=AVERAGE&host=true", context=ssl._create_unverified_context())

