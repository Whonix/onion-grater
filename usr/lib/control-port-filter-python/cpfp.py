#!/usr/bin/python

## Copyright (C) Amnesia <amnesia at boum dot org>
## Copyright (C) 2014 troubadour <trobador@riseup.net>
## Copyright (C) 2014 Patrick Schleizer <adrelanos@riseup.net>
## See the file COPYING for copying conditions.

# This filter proxy should allow Torbutton to request a
# new Tor circuit, without exposing dangerous control requests
# like "GETINFO address" to applications running as a local user.

# If something goes wrong, an error code is returned, and
# Torbutton will display a warning dialog that New Identity failed.

import gevent
from gevent import socket
from gevent.server import StreamServer
import binascii
import os
import glob
import logging
import signal
import sys


def signal_sigterm_handler():
    server.stop()
    logger.info('Signal sigterm received. Exiting.')
    sys.exit(143)


def signal_sigint_handler():
    server.stop()
    logger.info('Signal sigint received. Exiting.')
    sys.exit(130)


class configuration:
    def read(self):
        ## Read and override configuration from files
        if os.path.exists('/etc/cpfpy.d/'):
            files = sorted(glob.glob('/etc/cpfpy.d/*'))

            if files:
                RequestList = ''
                for conf in files:
                    if not conf.endswith('~') and conf.count('.dpkg-') == 0:
                        with open(conf) as c:
                            conf_file = conf
                            for line in c:
                                if line.startswith(
                                    'CONTROL_PORT_FILTER_DISABLE_FILTERING'):
                                    k, value = line.split('=')
                                    self.DISABLE_FILTERING = value.strip() == 'true'
                                if line.startswith(
                                    'CONTROL_PORT_FILTER_LIMIT_STRING_LENGTH'):
                                    k, value = line.split('=')
                                    self.LIMIT_STRING_LENGTH = int(value.strip())
                                if line.startswith(
                                    'CONTROL_PORT_FILTER_LIMIT_GETINFO_NET_LISTENERS_SOCKS'):
                                    k, value = line.split('=')
                                    self.LIMIT_GETINFO_NET_LISTENERS_SOCKS = value.strip() == 'true'
                                if line.startswith(
                                    'CONTROL_PORT_FILTER_WHITELIST'):
                                    k, value = line.split('=')
                                    # concatenate values from files, add a comma
                                    RequestList = RequestList + value.strip() + ','
                                if line.startswith(
                                    'CONTROL_PORT_FILTER_PORT'):
                                    k, value = line.split('=')
                                    self.PORT = int(value.strip())
                                if line.startswith(
                                    'CONTROL_PORT_FILTER_IP'):
                                    k, value = line.split('=')
                                    self.IP = str(value.strip())
                                if line.startswith(
                                    'CONTROL_PORT_SOCKET'):
                                    k, value = line.split('=')
                                    self.SOCKET = str(value.strip())
                                if line.startswith(
                                    'CONTROL_PORT_AUTH_COOKIE'):
                                    k, value = line.split('=')
                                    self.AUTH_COOKIE = str(value.strip())
                                if line.startswith(
                                    'CONTROL_PORT_FILTER_CONCURRENT_CONNECTIONS_LIMIT'):
                                    k, value = line.split('=')
                                    self.CONTROL_PORT_FILTER_CONCURRENT_CONNECTIONS_LIMIT = int(value.strip())

                ## Disable limit.
                if self.LIMIT_STRING_LENGTH == -1:
                    # "sock.recv()" requires an argument. 64 KB, arbitrary.
                    self.LIMIT_STRING_LENGTH = 65536

                self.WHITELIST = RequestList.split(',')
                ## Remove last element (comma)
                self.WHITELIST.pop()
                ## Remove duplicates
                self.WHITELIST = list(set(self.WHITELIST))

            else:
                self.set_default()
                return('No file found in user configuration folder "/etc/cpfpy.d".'\
                        ' Running with default configuration.')

        else:
            self.set_default()
            return('User configuration folder "/etc/cpfpy.d" does not exist.'\
                    ' Running with default configuration.')

        return('Configuration read from "%s"' % (conf_file))


    def set_default(self):
        ## Default control port filer configuration
        self.IP = '10.152.152.10'
        self.PORT = 9052
        self.SOCKET = '/var/run/tor/control'
        self.AUTH_COOKIE = '/var/run/tor/control.authcookie'
        selfDISABLE_FILTERING = False
        self.LIMIT_STRING_LENGTH = 16384
        self.LIMIT_GETINFO_NET_LISTENERS_SOCKS = True
        self.WHITELIST = ['signal newnym', 'getinfo net/listeners/socks',
                    'getinfo status/bootstrap-phase',
                    'getinfo status/circuit-established', 'quit']
        self.CONTROL_PORT_FILTER_CONCURRENT_CONNECTIONS_LIMIT = 5

    
class UnexpectedAnswer(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "[UnexpectedAnswer] " + self.msg


def do_request_real(request):
    ## Check if tor socket exists
    if not os.path.exists(configuration.SOCKET):
        logger.critical('Tor socket: "%s" does not exist' % (configuration.SOCKET))
        return

    ## The "lie" implemented in cpfp-bash
    if request == ('getinfo net/listeners/socks' and
                    configuration.LIMIT_GETINFO_NET_LISTENERS_SOCKS):
        temp = '250-net/listeners/socks="127.0.0.1:9150"\n'
        logger.info('Lying: %s' % (temp.strip()))
        return(temp)

    ## Read authentication cookie
    with open(configuration.AUTH_COOKIE, "rb") as f:
        rawcookie = f.read(32)
        hexcookie = binascii.hexlify(rawcookie)

        ## Connect to the real control port
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10.0)
        sock.connect(configuration.SOCKET)
        readh = sock.makefile("r")
        writeh = sock.makefile("w")

        ## Authenticate
        writeh.write("AUTHENTICATE " + hexcookie + "\n")
        writeh.flush()
        answer = readh.readline()
        if not answer.strip() == "250 OK":
            raise UnexpectedAnswer("AUTHENTICATE failed")

        ## Send the request
        writeh.write(request + '\n')
        writeh.flush()
        answer = sock.recv(configuration.LIMIT_STRING_LENGTH)

        sock.close()
        return answer


def do_request(request):
    logger.info('Request: %s' % (request.strip()))
    ## Catch innocent exceptions, will report error instead
    try:
        answer = do_request_real(request)
        logger.info('Answer: %s' % (answer.strip()))
        return answer
    except (IOError, UnexpectedAnswer) as e:
        logger.error(e)


def handle(sock, address):
    fh = sock.makefile()
    ## Keep accepting requests
    while True:
        ## Read in a newline terminated line
        rline = fh.readline()
        if not rline:
            break
        ## Strip escaped chars and white spaces.
        ## Convert to lowercase.
        request = rline.lower().strip()

        ## Authentication request.
        if request.startswith("authenticate"):
            # Don't check authentication, since only
            # safe requests are allowed
            fh.write("250 OK\n")

        elif configuration.DISABLE_FILTERING:
            ## Pass all requests
            answer = do_request(request)
            fh.write(answer)

        elif request in configuration.WHITELIST:
            ## Filtering enabled
            answer = do_request(request)
            fh.write(answer)

        else:
            ## Everything else we ignore/block
            fh.write("510 Request filtered\n")
            logger.info('Request: %s' % (request.strip()))
            logger.warning('Answer: 510 Request filtered "%s"' % (request))

        ## Ensure the answer was written
        fh.flush()

    ## Ensure all data was written
    fh.flush()

if __name__ == "__main__":
    pid = os.getpid()

    ## Create logger
    ##   Logger available levels:
    ##    .info
    ##    .warning
    ##    .error
    ##    .critical
    ##    .debug
    logging.basicConfig(filename='/var/log/control-port-filter-python.log',
                        level=logging.NOTSET)
    logger = logging.getLogger(unicode(pid))

    gevent.signal(signal.SIGTERM, signal_sigterm_handler)
    gevent.signal(signal.SIGINT, signal_sigint_handler)

    configuration = configuration()
    message = configuration.read()
    logger.info(message)

    ## Catch server exceptions.
    try:
        logger.info("Trying to start Tor control port filter on IP %s port %s"
                     % (configuration.IP, configuration.PORT))
        ## ACCEPT CONCURRENT CONNECTIONS.
        ## limit to 5 simultaneous connections.
        server = StreamServer((configuration.IP, configuration.PORT), handle,
                               spawn=configuration.CONTROL_PORT_FILTER_CONCURRENT_CONNECTIONS_LIMIT)

        logger.info("Tor control port filter started, listening on IP %s port %s"
                     % (configuration.IP, configuration.PORT))
        server.serve_forever()

    except Exception as e:
        logger.critical('Server error %s' % (e))
        logger.critical('Exiting.')
        sys.exit(1)
