# Include the libraries for socket and system calls
import socket
import sys
import os
import argparse
import re
import mimetypes
from datetime import datetime
from datetime import timedelta, timezone
import json
from email.utils import parsedate_to_datetime

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
  parts = resourceParts[0].split(":")
  hostname = parts[0]
  port = 80 if len(parts) == 1 else int(parts[1])
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
    cacheFile = open(cacheLocation, "rb")
    cacheData = cacheFile.read()

    print ('Cache hit! Loading from cache file: ' + cacheLocation)
    # ProxyServer finds a cache hit
    # Send back response to client 
    # ~~~~ INSERT CODE ~~~~
    with open(cacheLocation +".meta", 'r') as metafile:
      metadata = json.load(metafile)
      stored_at = datetime.fromisoformat(metadata["stored_at"])
      max_age = metadata.get("max_age", -1)
      expires = metadata.get("expires", -1)
      now = datetime.now(timezone.utc)
      is_fresh = (max_age == -1 or (stored_at + timedelta(seconds=max_age)) > now) and (expires == -1 or (datetime.fromisoformat(expires) > now))
      if not is_fresh:
        print("Entry in Cache is past max age")
        cacheFile.close()
        raise Exception("Cache entry past max age")

    ## creating the reponse
    clientSocket.sendall(cacheData) # sendall to make sure everything is sent

    # ~~~~ END CODE INSERT ~~~~
    cacheFile.close()
    print ('Sent to the client:')
    print ('> ' + cacheData.decode('utf-8'))
  except Exception as e:
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
          key, value = line.split(":",1)
          headers[key.strip().lower()] = value.strip()
        return headers, body
      
      chunk_headers, chunk_body = parse_response(chunk)

      while chunk:
        response += chunk
        chunk = originServerSocket.recv(BUFFER_SIZE)
        chunk_headers, chunk_body = parse_response(chunk)
      # ~~~~ END CODE INSERT ~~~~

        # - if the response is not complete (according to content length described in headers) 
        # check if the status of the response is 200, if it is then you cant serve it according to RFC 
        # 13.8, in that case send a 502 response ("origin served incomplete response or something")
        # otherwise serve it

      
      # Send the response to the client
      # ~~~~ INSERT CODE ~~~~
      # check if its incomplete
      response_headers, response_body = parse_response(response)

      content_length = int(response_headers.get("content-length", -1))
      actual_length = len(response_body)
      is_incomplete = content_length != -1 and actual_length < content_length

      status_line = response_headers.get("status", "")
      status_code = int(status_line.split()[1]) if status_line else 0
      # MUST NOT serve incomplete with 200 code
      if is_incomplete and status_code == 200:
        error_response = (
            "HTTP/1.1 502 Bad Gateway\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: 50\r\n\r\n"
            "Origin server returned incomplete response."
        ).encode("utf-8")

        clientSocket.sendall(error_response)
      else: 
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

      # dont neeed to worry about this authorization, since at the moment cache doesn't support requestheaders

      cacheable = ("no-store" not in response_headers.get("cache-control", "").lower() and 
                   "private" not in response_headers.get("cache-control", "").lower() and 
                   ("expires" in response_headers or 
                    "max-age" in response_headers.get("cache-control", "").lower() or 
                    "s-maxage" in response_headers.get("cache-control", "").lower() or
                    "must-understand" in response_headers.get("cache-control", "").lower() or 
                    any(code == status_code for code in [200, 203, 204, 206, 300, 301, 304, 308, 404, 405, 410, 414, 501])))
      # make sure not incomplete
      # according to RFC 9111 3.3, must not store if partial or incomplete since we dont handle ranges
      if is_incomplete or (status_code == 206): cacheable = False

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
        cache_control = response_headers.get("cache-control", "")
        matches = re.search(r'max-age\s*=\s*(\d+)', cache_control) # extract seconds from max-age=<seconds>
        max_age = int(matches.group(1)) if matches else -1
        now = datetime.now(timezone.utc)
        expires = response_headers.get('expires')
        expires_at = -1 if expires is None else parsedate_to_datetime(expires).isoformat()
        metadata = {
            "expires": expires_at,
            "stored_at": now.isoformat(),
            "max_age": max_age,
            "status_code": status_code,
            "etag": response_headers.get("etag"),
            "incomplete": False
        }
        with open(cacheLocation+".meta", "w") as metafile:
          json.dump(metadata, metafile)
        
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
