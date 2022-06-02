import socket
import sys
import os.path
import datetime

HOST = '127.0.0.1'
PORT = int(sys.argv[1])

def filerequest(conn): 
    data = bytearray(conn.recv(1024))
    if (data[0] << 8) | data[1] != 0x497E:
        return -1 
    elif data[2] != 1:
        print("ERROR: invalid record type!")
        return -1, -1 
    elif len(data[3] << 8) | data[4] > 1024:
        print("ERROR: invalid filename size!")
        return -1, -1
    n = (data[3] << 8) | data[4]
    file_name = data[5:]
    while len(file_name) != n:
        data = bytearray(conn.recv(1024))
        file_name += data[5:]
    return name, n
                     
    
def fileresponse(valid, server_socket, contents=''): 
    if valid is True: 
        contents = bytearray(contents, "utf-8")
        header = bytearray((0x497E << 48) + (2 << 40) + (1 << 32) + len(contents)).to_bytes(8, "big")
        first = True
        bytecount = 0
        while len(contents) >= 88 or first == True:
            pkt = header + contents[:88]
            server_socket.sendall(pkt)
            contents = contents[88:]
            first = False
            bytecount += len(pkt)
        if len(contents) != 0:
            pkt2 = header + contents
            server_socket.sendall(pkt2)
            bytecount += len(pkt2)
        print(bytecount, "bytes sent.\n")
        return bytecount
    else:
        server_socket.sendall(bytearray((0x497E << 48) + (2 << 40) + (0 << 32) +  len(contents)).to_bytes(8, "big"))
        print("ERROR: file does not exist or cannot be opened!")
    
def openfile(filename):
    file = open(filename, 'r')
    contents = file.read()
    file.close()
    return contents

def server(port):
    if port < 1024 or port > 64000: #should be between and including
        print("ERROR: invalid port number!")
        sys.exit(0)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates a socket
    try:
        server_socket.bind((HOST, port)) #binds socket to port number
    except:
        print("ERROR: socket binding unsuccessful!")
        sys.exit(0)
    try:
        server_socket.listen() #calls listen()
    except:
        print("ERROR: socket listening unsuccessful!")
        sys.exit(0)
    loop = 0 #enters infinite loop
    while loop is 0:
        conn, addr = server_socket.accept() #accept()s a new incoming connection
        print("Connected by", addr)
        try:
            dataarray, n = filerequest(conn) #tries to read FileRequest record from the connection
            if dataarray != -1:
                filename = dataarray.decode("utf-8")
                print("Filename:", filename)
                if len(dataarray) != n:
                    print("ERROR: record invalid or data size cannot be read!")
                    conn.close()
                if os.path.exists(filename): #if the file exists
                    print("File opened successfully!")
                    byte_count = fileresponse(True, conn, contents)
                    contents = openfile(filename)
                    conn.close()
                else:
                    fileresponse(False, conn)
                    conn.close()
                    print("ERROR: file does not exist or cannot be opened!")
            else:
                conn.close()
        except:
            fileresponse(False, conn)
            conn.close()
            
server(PORT)
                    