"""Expose the fixture frontend at the debug shell's configured local origin."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.request import urlopen,Request
import os
class Proxy(BaseHTTPRequestHandler):
 def do_GET(self):
  try:
   with urlopen(os.environ.get('SIRINVPN_CATALOG_URL','http://127.0.0.1:1422')+self.path) as r:
    body=r.read();self.send_response(r.status)
    for k,v in r.headers.items():
     if k.lower() not in ['transfer-encoding','content-length','connection']:self.send_header(k,v)
    self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  except Exception as error:self.send_error(502,str(error))
 def log_message(self,*args):pass
ThreadingHTTPServer(('127.0.0.1',1420),Proxy).serve_forever()
