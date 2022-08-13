# https://svn.python.org/projects/sandbox/trunk/digestauth/httpserver.py
from http.server import SimpleHTTPRequestHandler
#import SimpleHTTPServer, BaseHTTPServer

import digestauth

digester = digestauth.DigestAuthServer(default_realm='TestAuth', algorithm='MD5')
#digester.parse_apache_digest_authfile('/var/www/passwords')

class DigestAuthHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, directory=self.directory)

    def do_GET(self, *args):
        path = self.path

        if True:#path.startswith("/test"):
            if 'Authorization' not in self.headers:
                self.send_auth('auth required')
                return
            else:
                auth = self.headers['Authorization']
                if auth.split()[0].lower() == 'digest':
                    ok, reason = digester.check_auth(auth[7:])
                    if not ok:
                        self.send_auth('auth failed: %s'%reason)
                        return
                    else:
                        SimpleHTTPRequestHandler.do_GET(self)
        # else:
        # self.send_response(200)
        # self.send_header("Content-type", "text/plain")
        # self.end_headers()
        # self.wfile.write(("all good: %s\n"%path).encode('ascii'))

    def send_auth(self, text):
        self.send_response(401)
        chal = digester.generate_challenge()
        self.send_header('WWW-Authenticate', 'Digest %s'%(chal))
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(('<html><body><p>'+text+'\n\n</p></body></html>').encode('ascii'))
        return


# def run(server_class=BaseHTTPServer.HTTPServer,
#         handler_class=Handler):
#     server_address = ('', 8000)
#     httpd = server_class(server_address, handler_class)
#     httpd.serve_forever()

# run()
