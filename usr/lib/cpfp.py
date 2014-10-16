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

# Only one application can talk through this filter proxy
# simultaneously. A malicious application that is running as a
# local user could use this to prevent other applications from
# doing NEWNYM. But it could just as well rewrite the
# TOR_CONTROL_PORT environment variable to itself or do something else.

import socket
import SocketServer
import binascii
import os
import glob



class UnexpectedAnswer(Exception):

    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "[UnexpectedAnswer] " + self.msg



class TCPHandler(SocketServer.StreamRequestHandler):
    
    def check_answer(self,  answer):
        # Check length only. Could be refined later.
        if len(answer) > MAX_LINESIZE:
            # the answer is too long for the settings. Reject.
            return False
        return True


    def do_request_real(self,  request):
        # check if tor socket exists
        if not os.path.exists(SOCKET):
            reply = "255 tor is not running"
            print "tor is not running"
            return reply + '\r\n'
        # Read authentication cookie
        with open(AUTH_COOKIE, "rb") as f:
            rawcookie = f.read(32)
            hexcookie = binascii.hexlify(rawcookie)

            # Connect to the real control port
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            sock.connect(SOCKET)
            readh = sock.makefile("r")
            writeh = sock.makefile("w")

            # Authenticate
            writeh.write("AUTHENTICATE " + hexcookie + "\n")
            writeh.flush()
            answer = readh.readline()
            # strict answer check ('==' instead of '.startwith()'
            if not answer.strip() == "250 OK":
                raise UnexpectedAnswer("AUTHENTICATE failed")

            # The "lie" implemented in cpfp-tcpserver
            if request == 'GETINFO net/listeners/socks' and \
                LIMIT_GETINFO_NET_LISTENERS_SOCKS:
                    return('250-net/listeners/socks="127.0.0.1:9150"\n')

            # Send the request
            writeh.write(request + '\n')
            writeh.flush()
            answer = readh.readline()
            if not answer.startswith("250"):
                raise UnexpectedAnswer("Request failed: " + request)
            if not self.check_answer(answer):
                raise UnexpectedAnswer("Request '" + request  + "': Answer too long '" + answer + "'")
            reply = answer

            # Close the connection
            # Some requests return "250 OK" and close the connection.
            # 'SIGNAL NEWNYM' is an example.
            if not answer.strip() == "250 OK":
               writeh.write("QUIT\n")
               writeh.flush()
               answer = readh.readline()
               if not answer.strip() == "250 OK":
                   raise UnexpectedAnswer("QUIT failed")
            # answer terminated with '250 OK'
            reply = reply + answer

            sock.close()

            return reply


    def do_request(self, request):
        # Catch innocent exceptions, will report error instead
        try:
            answer = self.do_request_real(request)
            print "Request went fine"
            return answer
        except (IOError, UnexpectedAnswer) as e:
            print "Warning: Couldn't perform Request!"
            print e
            return e


    def handle(self):
        # Keep accepting requests
        while True:
            # Read in a newline terminated line
            line = self.rfile.readline()
            if not line:
                break
            # Strip escaped chars and white spaces at beginning and end of string
            request = line.strip()
            # Authentication request from Tor Browser.
            if request.startswith("AUTHENTICATE"):
                # Don't check authentication, since only
                # safe requests are allowed
                self.wfile.write("250 OK\n")

            elif request in WHITELIST:
                # Perform a real request)
                answer = self.do_request(request)
                self.wfile.write(answer)

            elif request == "QUIT":
                # Quit session
                self.wfile.write("250 Closing connection\n")
                #break

            else:
                # Everything else we ignore/block
                self.wfile.write("510 Request filtered\n")

            # Ensure the answer was written
            self.wfile.flush()

        # Ensure all data was written
        self.wfile.flush()



if __name__ == "__main__":
    
    #if not os.path.exists('/etc/cpfpy.d/'):
    #    print 'Configuration folder does not exist'
    #    raise UnexpectedAnswer('Configuration folder does not exist')

    files = sorted(glob.glob('/etc/cpfpy.d/*'))
    #if not files  :
    #    print 'No configuration file in "/etc/cpfpy.d"'
    #    raise UnexpectedAnswer('Configuration file does not exist')
    RequestList = ''

    for conf in files:
        if not conf.endswith('~') and conf.count('.dpkg-') == 0:
            with open(conf) as f:
                for line in f:
                    if line.startswith('CONTROL_PORT_FILTER_LIMIT_GETINFO_NET_LISTENERS_SOCKS'):
                        k, value = line.split('=')
                        LIMIT_GETINFO_NET_LISTENERS_SOCKS = value.strip() == 'true'
                    if line.startswith('CONTROL_PORT_FILTER_LIMIT_STRING_LENGTH'):
                        k, value = line.split('=')
                        LIMIT_STRING_LENGTH = value.strip() == 'true'
                    if line.startswith('CONTROL_PORT_FILTER_EXCESSIVE_STRING_LENGTH'):
                        k, value = line.split('=')
                        EXCESSIVE_STRING_LENGTH = int(value.strip())
                    if line.startswith('CONTROL_PORT_FILTER_WHITELIST'):
                        k, value = line.split('=')
                        # concatenate values from files, add a comma
                        RequestList = RequestList + value.strip() + ','
                    if line.startswith('CONTROL_PORT_FILTER_PORT'):
                        k, value = line.split('=')
                        PORT = int(value.strip())
                    if line.startswith('CONTROL_PORT_FILTER_IP'):
                        k, value = line.split('=')
                        IP = str(value.strip())
                    if line.startswith('CONTROL_PORT_SOCKET'):
                        k, value = line.split('=')
                        SOCKET = str(value.strip())
                    if line.startswith('CONTROL_PORT_AUTH_COOKIE'):
                        k, value = line.split('=')
                        AUTH_COOKIE = str(value.strip())

    WHITELIST = RequestList.split(',')
    # remove last element (comma)
    WHITELIST.pop()
    # remove duplicates
    WHITELIST = list(set(WHITELIST))

    if  LIMIT_STRING_LENGTH:
        # used in check_answer()
        MAX_LINESIZE = EXCESSIVE_STRING_LENGTH
    else:
        # In my tests, the answer from "net_listeners_socks" was 1849 bytes long.
        MAX_LINESIZE = 2048

    #print MAX_LINESIZE

    # This configuration would truncate "net_listeners_socks" answer and raise an exception,
    # Tor Button will be disabled.
    if  LIMIT_STRING_LENGTH and \
        not LIMIT_GETINFO_NET_LISTENERS_SOCKS:
            raise UnexpectedAnswer("Invalid configuration")

    # Starts a TCP server 
    print "Trying to start Tor control port filter on IP %s port %s" % (IP, PORT)
    server = SocketServer.TCPServer((IP, PORT), TCPHandler)

    print "Tor control port filter started, listening on IP %s port %s" % (IP, PORT)
    # Accept parallel connections.
    server.serve_forever()
