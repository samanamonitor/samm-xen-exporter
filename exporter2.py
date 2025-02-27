
xen=XenAPI.Session(f"https://{xen_host}", ignore_ssl=not exporter.verify_ssl)
xen.xenapi.login_with_password(xen_user, xen_password)

# get full RRD
res=urllib.request.urlopen(f"https://{exporter.xen_host}/host_rrd?session_id={xen._session}&json=true", context=ssl._create_unverified_context())
data=json.load(res)

xenhosts=xen.xenapi.host.get_all()
list = []
for host in xenhosts:
      list.append(xen.xenapi.PIF.get_record(xen.xenapi.host.get_management_interface(host))['IP'])

vmuuid=xen.xenapi.VM.get_record(xen.xenapi.host.get_resident_VMs(xen.xenapi.host.get_all()[0])[0])['uuid']
# VM full RRD
res=urllib.request.urlopen(f"https://{exporter.xen_host}/vm_rrd?session_id={xen._session}&uuid={vmuuid}&json=true", context=ssl._create_unverified_context())

# get only updates
res=urllib.request.urlopen(f"https://{exporter.xen_host}/rrd_updates?session_id={xen._session}&json=true&start={int(time.time()) - 10}&cf=AVERAGE&host=true", context=ssl._create_unverified_context())

