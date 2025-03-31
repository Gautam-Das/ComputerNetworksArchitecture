# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import mimetypes
from datetime import datetime

# 1MB buffer size
BUFFER_SIZE = 1000000

# Get the IP address and Port number to use for this web proxy server
parser = argparse.ArgumentParser()
parser.add_argument('hostname', help='the IP Address Of Proxy Server')
parser.add_argument('port', help='the port number of the proxy server')
args = parser.parse_args()
proxyHost = args.hostname
proxyPort = int(args.port)
print(proxyPort)

socket_obj = None

# Create a server socket, bind it to a port and start listening
try:
  # Create a server socket
  # ~~~~ INSERT CODE ~~~~
  socket_obj = socket.socket()
  # ~~~~ END CODE INSERT ~~~~
  print ('Created socket')
except:
  print ('Failed to create socket')
  sys.exit()

try:
  # Bind the the server socket to a host and port
  # ~~~~ INSERT CODE ~~~~
  socket_obj.bind((proxyHost, proxyPort))
  # ~~~~ END CODE INSERT ~~~~
except Exception as e:
  print('Port is already in use')
  sys.exit()

try:
  # Listen on the server socket
  # ~~~~ INSERT CODE ~~~~
  # max 3 queued incomming connections,
  # don't expect more than 1 but just in case
  socket_obj.listen(3)  
  # ~~~~ END CODE INSERT ~~~~
  print ('Listening to socket')
except:
  print ('Failed to listen')
  sys.exit()

# continuously accept connections
while True:
  print ('Waiting for connection...')
  clientSocket = None
  clientAddress = None

  # Accept connection from client and store in the clientSocket
  try:
    # ~~~~ INSERT CODE ~~~~
    clientSocket, clientAddress = socket_obj.accept()
    # ~~~~ END CODE INSERT ~~~~
    print ('Received a connection')
  except:
    print ('Failed to accept connection')
    sys.exit()

  # Get HTTP request from client
  # and store it in the variable: message_bytes
  # ~~~~ INSERT CODE ~~~~
  message_bytes = clientSocket.recv(BUFFER_SIZE)
  # ~~~~ END CODE INSERT ~~~~
  message = message_bytes.decode('utf-8')
  print ('Received request:')
  print ('< ' + message)

  # Extract the method, URI and version of the HTTP client request 
  requestParts = message.split()
  method = requestParts[0]
  URI = requestParts[1]
  version = requestParts[2]

  print ('Method:\t\t' + method)
  print ('URI:\t\t' + URI)
  print ('Version:\t' + version)
  print ('')

  # Get the requested resource from URI
  # Remove http protocol from the URI
  URI = re.sub('^(/?)http(s?)://', '', URI, count=1)

  # Remove parent directory changes - security
  URI = URI.replace('/..', '')

  # Split hostname from resource name
  resourceParts = URI.split('/', 1)
  hostname = resourceParts[0]
  resource = '/'

  if len(resourceParts) == 2:
    # Resource is absolute URI with hostname and resource
    resource = resource + resourceParts[1]

  print ('Requested Resource:\t' + resource)

  # Check if resource is in cache
  try:
    cacheLocation = './' + hostname + resource
    if cacheLocation.endswith('/'):
        cacheLocation = cacheLocation + 'default'

    print ('Cache location:\t\t' + cacheLocation)

    fileExists = os.path.isfile(cacheLocation)

    # Check wether the file is currently in the cache
    cacheFile = open(cacheLocation, "r")
    cacheData = cacheFile.readlines()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    
    ## creating the reponse
    clientSocket.sendall("".join(cacheData)) # sendall to make sure everything is sent

    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + "".join(cacheData))
  except:
    # cache miss.  Get resource from origin server
    originServerSocket = None
    # Create a socket to connect to origin server
    # and store in originServerSocket
    # ~~~~ INSERT CODE ~~~~
    originServerSocket = socket.socket()
    # ~~~~ END CODE INSERT ~~~~

    print ('Connecting to:\t\t' + hostname + '\n')
    try:
      # Get the IP address for a hostname
      address = socket.gethostbyname(hostname)
      # Connect to the origin server
      # ~~~~ INSERT CODE ~~~~
      originServerSocket.connect((address,80)) # typically port 80 for http
      # ~~~~ END CODE INSERT ~~~~
      print ('Connected to origin Server')

      originServerRequest = ''
      originServerRequestHeader = ''
      # Create origin server request line and headers to send
      # and store in originServerRequestHeader and originServerRequest
      # originServerRequest is the first line in the request and
      # originServerRequestHeader is the second line in the request
      # ~~~~ INSERT CODE ~~~~
      # print(method, resource, version, hostname)
      originServerRequest = f"{method} {resource} {version}"
      originServerRequestHeader = f"Host: {hostname}\r\nConnection: close"

      # ~~~~ END CODE INSERT ~~~~

      # Construct the request to send to the origin server
      request = originServerRequest + '\r\n' + originServerRequestHeader + '\r\n\r\n'

      # Request the web resource from origin server
      print ('Forwarding request to origin server:')
      for line in request.split('\r\n'):
        print ('> ' + line)

      try:
        originServerSocket.sendall(request.encode())
      except socket.error:
        print ('Forward request to origin failed')
        sys.exit()

      print('Request sent to origin server\n')

      # Get the response from the origin server
      # ~~~~ INSERT CODE ~~~~
      response = b''
      chunk = originServerSocket.recv(BUFFER_SIZE)
      prev_response_date = None
      
      def parse_response(chunk):
        try:
          header_raw, body = chunk.split(b'\r\n\r\n', 1)
        except ValueError:
            return {}, chunk

        # evidently utf8 has some edge cases that might fail
        header_lines = header_raw.decode('iso-8859-1').split('\r\n')

        status = header_lines[0]
        headers = {"status" : status}
        for line in header_lines:
          if ":" not in line: continue
          key, value = line.split(":")
          headers[key.strip().lower()] = value.strip()
        return headers, body
      
      chunk_headers, chunk_body = parse_response(chunk)


      ## according to RFC 13.5.4 if multiple response are received the cahce MAY combine them
      ## I have chosen not to, since it works in more cases without having to delve into validators
      while chunk:
        current_chunk_date = datetime.strptime(chunk_headers['date'], "%a, %d %b %Y %H:%M:%S GMT")
        if not prev_response_date:
          prev_response_date = current_chunk_date # following RFC format
          response = chunk
        elif prev_response_date < current_chunk_date:
          prev_response_date = current_chunk_date
          response = chunk
        chunk = originServerSocket.recv(BUFFER_SIZE)
        chunk_headers, chunk_body = parse_response(chunk)
      # ~~~~ END CODE INSERT ~~~~

        # - if the response is not complete (according to content length described in headers) 
        # check if the status of the response is 200, if it is then you cant serve it according to RFC 
        # 13.8, in that case send a 502 response ("origin served incomplete response or something")
        # otherwise serve it


      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      clientSocket.sendall(response)
      # ~~~~ END CODE INSERT ~~~~

      

      # cache needs to act as a mediator first so just forward whatever response was received


        # cache if:
        # response status is understood by the cache
        # no-store is not in the header
        # private is not in the response directive
        # if the response status code is 206 or 304, or the must-understand cache directive is present
        # contains: Expires, max-age/s-maxage response directive, cache control extension, 
        # or status code that is cacheable by default: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, and 501

      response_headers, response_body = parse_response(response)
      # dont neeed to worry about this authorization, since at the moment cache doesn't support requestheaders
      status_line = response_headers.get("status", "")
      status_code = int(status_line.split()[1]) if status_line else 0
      cacheable = ("no-store" not in response_headers.get("cache-control", "").lower() and 
                   "private" not in response_headers.get("cache-control", "").lower() and 
                   ("expires" in response_headers or 
                    "max-age" in response_headers.get("cache-control", "").lower() or 
                    "s-maxage" in response_headers.get("cache-control", "").lower() or
                    "must-understand" in response_headers.get("cache-control", "").lower() or 
                    any(code == status_code for code in [200, 203, 204, 206, 300, 301, 304, 308, 404, 405, 410, 414, 501])))




      # Create a new file in the cache for the requested file.
      if cacheable:
        cacheDir, file = os.path.split(cacheLocation)
        print ('cached directory ' + cacheDir)
        if not os.path.exists(cacheDir):
          os.makedirs(cacheDir)
        cacheFile = open(cacheLocation, 'wb')

        # Save origin server response in the cache file
        # ~~~~ INSERT CODE ~~~~
        cacheFile.write(response)
        # ~~~~ END CODE INSERT ~~~~
        cacheFile.close()
        print ('cache file closed')

      # finished communicating with origin server - shutdown socket writes
      print ('origin response received. Closing sockets')
      originServerSocket.close()
       
      clientSocket.shutdown(socket.SHUT_WR)
      print ('client socket shutdown for writing')
    except OSError as err:
      print ('origin server request failed. ' + err.strerror)

  try:
    clientSocket.close()
  except:
    print ('Failed to close client socket')
