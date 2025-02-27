import urllib.request
import sys, os
import time
import ssl
import json

xen_password = os.getenv("XEN_PASSWORD", "")
xen_user = os.getenv("XEN_USER", "root")
xen_host = os.getenv("XEN_HOST", "localhost")
xen_mode = os.getenv("XEN_MODE", "host")
verify_ssl = True if os.getenv("XEN_SSL_VERIFY", "true").lower() == "true" else False


class XenRrd:
    def __init__(self, host, user, password, verify_ssl=True):
        self._host = host
        ctx = ssl.create_default_context()
        if not verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        sslhandler = urllib.request.HTTPSHandler(context=ctx)

        pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        top_level_url = f"https://{host}"
        pm.add_password(None, top_level_url, user, password)
        authhandler = urllib.request.HTTPBasicAuthHandler(pm)

        self._opener = urllib.request.build_opener(sslhandler, authhandler)

    @property
    def data(self):
        url = f"https://{self._host}/rrd_updates?start={int(time.time()-10)}&json=true&host=true&cf=AVERAGE"
        print(url)
        res = self._opener.open(url)
        return json.load(res)

x = XenRrd(xen_host, xen_user, xen_password, verify_ssl)
