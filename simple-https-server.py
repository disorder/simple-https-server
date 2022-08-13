#!/usr/bin/env python3
#
#       Author:		    Chase Schultz
#       Handle:		    f47h3r
#       Date:		    03/31/2018
#       Description:        Python SimpleHTTPServer Served over HTTPS with Basic Auth
#
# 	Usage:
#
#               A Lets Encrypt TLS certificate can be generated with the following commands:
#
#                   sudo certbot certonly --register-unsafely-without-email --standalone -d <domain_name>
#                   sudo cat /etc/letsencrypt/live/<domain_name>/fullchain.pem > server.pem
#                   sudo cat /etc/letsencrypt/live/<domain_name>/privkey.pem >> server.pem
#
#               Alternatively a self signed certificate can be generated with the following command:
#
#                   openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
#
#               Generate Basic Auth Key:
#
#                   echo -n "<username>:<password>" | base64
#
# 		Run as follows:
#
#                   python simple-https-server_basic-auth.py
#
# 		In your browser, visit:
#
#                   https://localhost:4443
#

from httpserver import DigestAuthHandler, digester, ChildHandler
import argparse
import os
import ssl
import logging
import http.server

from base64 import b64decode, b64encode

# Logging Setup
#logging.basicConfig(filename='simple.log', level=logging.DEBUG)

class BasicAuthHandler(ChildHandler):

    # Basic Auth Key ( !!Change Me!! -- admin/admin )
    key = 'YWRtaW46YWRtaW4='

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs, directory=self.directory)

    def do_HEAD(self):
        '''Send Headers'''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        '''Send Basic Auth Headers'''
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        '''Handle GET Request'''
        try:
            if self.headers.get('Authorization') is None:
                # Send Auth Headers
                self.do_AUTHHEAD()
                logger.debug('Auth Header Not Found')
                self.wfile.write(bytes('Unauthorized', 'utf8'))
            elif self.headers.get('Authorization') == 'Basic ' + self.key:
                # Successful Auth
                http.server.SimpleHTTPRequestHandler.do_GET(self)
            else:
                # Bad Credentials Supplied
                self.do_AUTHHEAD()
                auth_header = self.headers.get('Authorization')
                # Log Bad Credentials
                if len(auth_header.split(' ')) > 1:
                    logger.debug(auth_header.split(' ')[1])
                    logger.debug(b64decode(auth_header.split(' ')[1]))
                logger.debug('Bad Creds')
                self.wfile.write(bytes('Unauthorized', 'utf8'))
        except Exception:
            logger.error("Error in GET Functionality", exc_info=True)

    def date_time_string(self, time_fmt='%s'):
        return ''

    def log_message(self, format, *args):
        '''Requests Logging'''
        logger.info("%s - - [%s] %s" % (
            self.client_address[0],
            self.log_date_time_string(),
            format % args))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('--bind', dest='bind', action='store', default='0.0.0.0',
                        help='IP address to bind to')
    parser.add_argument('--port', dest='port', action='store', type=int,
                        default=8443,
                        help='Port to listen')
    parser.add_argument('--user', dest='user', action='store', required=True,
                        help='AUTH user')
    parser.add_argument('--pass', dest='password', action='store', required=True,
                        help='AUTH password')
    parser.add_argument('--cert', dest='certfile', action='store', required=True,
                        help='Path to certificate')
    parser.add_argument('--key', dest='keyfile', action='store', required=True,
                        help='Path to private key')
    parser.add_argument('--path', dest='path', action='store', default=None,
                        help='Path with files to be served')
    parser.add_argument('--loglevel', dest='loglevel', action='store', default='INFO',
                        help='Log level')
    parser.add_argument('--basic', dest='basic', action='store_true', default=False,
                        help='Basic HTTP auth')
    parser.add_argument('--digest', dest='digest', action='store_true', default=False,
                        help='Digest HTTP auth')
    parser.add_argument('--realm', dest='realm', action='store', default=None,
                        help='Digest HTTP auth realm')
    parser.add_argument('--http', dest='http', action='store_true', default=False,
                        help='Disable HTTPS')
    args = parser.parse_args()
    logging.basicConfig(level=logging.getLevelName(args.loglevel))
    logger = logging.getLogger()
    logger.info(args)

    # Create Handler Instance
    if args.digest:
        handler = DigestAuthHandler
        #from hashlib import sha1
        #hash = '{SHA}' + b64encode(sha1(args.password.encode('utf-8')).digest()).decode('ascii')
        #from hashlib import md5
        #hash = '{MD5}' + b64encode(md5(args.password.encode('utf-8')).digest()).decode('ascii')
        #digester.add_user_hash(args.user, hash, args.realm)
        digester.add_user(args.user, args.password, args.realm)
    elif args.basic:
        handler = BasicAuthHandler
        handler.key = b64encode((args.user + ':' + args.password).encode('utf-8')).decode('ascii')
    else:
        #handler = http.server.SimpleHTTPRequestHandler
        handler = ChildHandler

    handler.directory = args.path

    # Spoof Server Header ( !!Change Me!! )
    #handler.server_version = ' '
    #handler.sys_version = ''

    # SimpleHTTPServer Setup
    #httpd = http.server.HTTPServer((args.bind, args.port), handler)class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    #import socketserver
    #class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    #    daemon_threads = True
    # this is supposed to fix hangs
    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), handler)
    #httpd.socket = ssl.wrap_socket(httpd.socket, certfile=args.certfile, keyfile=args.keyfile, server_side=True)
    ChildHandler.certfile = args.certfile
    ChildHandler.keyfile = args.keyfile
    ChildHandler.http = args.http
    try:
        httpd.serve_forever()
    except Exception:
        logger.error("Fatal error in main loop", exc_info=True)
