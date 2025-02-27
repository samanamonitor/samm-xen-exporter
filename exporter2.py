#!/usr/bin/python3

import XenAPI
import urllib
import ssl

class Xen:
      def __init__(self, host, user, password, verify_ssl=True):
            self._host = host
            self._verify_ssl = verify_ssl
            self.session = XenAPI.Session(f"https://{host}", ignore_ssl=not verify_ssl)
            self.session.xenapi.login_with_password(user, password)
            self.session_id = self.session._session

      @property
      def xenapi(self):
            return self.session.xenapi

      def getHostRRD(self, host):
            # get full RRD
            kwargs = {}
            if not self._verify_ssl:
                  kwargs['context'] = ssl._create_unverified_context()
            res=urllib.request.urlopen(f"https://{self._host}/host_rrd?session_id={self.session_id}&json=true", **kwargs)
            return json.load(res)

      def getVmRRD(self, host, vm):
            #xen.xenapi.host.get_resident_VMs(xen.xenapi.host.get_all()[0])[0])['uuid']
            kwargs = {}
            if not self._verify_ssl:
                  kwargs['context'] = ssl._create_unverified_context()
            vmuuid=xen.xenapi.VM.get_record(vm).get('uuid')
            if vmuuid is None:
                  raise ValueError(f"VM '{vm}' could not be found")
            host_ip = xen.xenapi.PIF.get_record(xen.xenapi.host.get_management_interface(host)).get('IP')
            if host_ip is None:
                  raise ValueError(f"Unable to get IP for host '{host}'")
            res=urllib.request.urlopen(f"https://{host_ip}/vm_rrd?session_id={self.session_id}&uuid={vmuuid}&json=true", **kwargs)

      def getUpdatesRRD(self, host):
            kwargs = {}
            if not self._verify_ssl:
                  kwargs['context'] = ssl._create_unverified_context()
            host_ip = xen.xenapi.PIF.get_record(xen.xenapi.host.get_management_interface(host)).get('IP')
            if host_ip is None:
                  raise ValueError(f"Unable to get IP for host '{host}'")
            res=urllib.request.urlopen(f"https://{host_ip}/rrd_updates?session_id={self.session_id}&json=true&start={int(time.time()) - 10}&cf=AVERAGE&host=true", **kwargs)

      def __enter__(self):
            return self

      def __exit__(self, exc_type, exc_value, traceback):
            self.session.xenapi.session.logout()


#xenhosts=xen.xenapi.host.get_all()
#list = []
#for host in xenhosts:
#      list.append(xen.xenapi.PIF.get_record(xen.xenapi.host.get_management_interface(host))['IP'])

# VM full RRD
#res=urllib.request.urlopen(f"https://{exporter.xen_host}/vm_rrd?session_id={xen._session}&uuid={vmuuid}&json=true", context=ssl._create_unverified_context())

# get only updates
#res=urllib.request.urlopen(f"https://{exporter.xen_host}/rrd_updates?session_id={xen._session}&json=true&start={int(time.time()) - 10}&cf=AVERAGE&host=true", context=ssl._create_unverified_context())

