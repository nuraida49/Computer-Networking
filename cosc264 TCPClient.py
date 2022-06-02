import socket
import sys
import os.path
import datetime

if len(sys.argv) != 4:
    print("ERROR: invalid number of parameters!")
    sys.exit(0)
    
HOST: str(sys.argv[1])
PORT: str(sys.argv[2])
FILENAME: str(sys.argv[3])

def fileresponse(client_socket):
    data = bytearray(client_socket.recv(1024))
    bytenum = 0
    if (data[0] << 8) | data[1] != 0x497E:
        print("ERROR: invalid MagicNo!")
        sys.exit(0)
    elif data[2] != 2:
        print("ERROR: invalid record type!")
        sys.exit(0)
    elif data[3] != 1:
        print("ERROR: file does not exist or cannot be opened!")
        sys.exit(0)
    else:
        contents_len = ((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7])
        contents = data[8:]
        bytenum += len(data)
        message = bytearray(client_socket.recv(1024))
        while len(message) != 0:
            bytenum += len(message)
            contents += message[8:]
            message = bytearray(client_socket.recv(1024))
        print("Data received successfully!")
        if len(contents) != contents_len:
            print("ERROR: invalid data length!")
            return -1
        else:
            print(bytenum, "bytes received!")
            return contents

def client(host, port, filename):
    try:
        socket_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        hostname = socket_info[-1]
        ip_port = hostname[-1]
        ip, num = ip_port
    except:
        print("ERROR: hostname does not exist or IP address not well-formed!")
        sys.exit(0)
    if port < 1024 or port > 64000: #should be between and including
        print("ERROR: invalid port number!")
        sys.exit(0)
    elif os.path.exists(filename): #check if file exists
        print("ERROR: file already exists!")
        sys.exit(0)
    else:
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates a socket
            client_socket.settimeout(1)
        except:
            print("ERROR: failed to create a socket!")
            sys.exit(0)
        try:
            client_socket.connect((host, port)) #connect with server
        except:
            client_socket.close()
            print("socket connecting unsuccessful!")
            sys.exit(0)
        file_name = bytearray(filename.encode("utf-8"))
        file_name_length = len(file_name)
        if file_name_length < 1024:
            filerequest = bytearray(((0x497E << 24) + (1 << 16) + (file_name_length)).to_bytes(5, "big"))
            filerequest += file_name
            client_socket.sendall(filerequest)
            contents = fileresponse(client_socket) #try to read FileResponse record
            if contents != -1:
                decoded = contents.decode("utf-8")
                files = open(filename, "w")
                files.write(decoded)
                files.close()
    sys.exit(0)
    
client(HOST, PORT, FILENAME)