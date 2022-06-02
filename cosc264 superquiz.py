#takes as parameters the real values to be filled into the packet, checks these parameters for validity (see below), and which returns either:an error code, i.e. an integer specifying a particular error in the parameters handed to the function, or a bytearray of 20 bytes length containing the standard IPv4 header (without optional fields), which is only to be returned when all validity checks have passed.

def composepacket (version, hdrlen, tosdscp, totallength, identification, flags, fragmentoffset, timetolive, protocoltype, headerchecksum, sourceaddress, destinationaddress):
    if version != 4:
        return 1
    elif hdrlen < 0 or hdrlen > 2**4-1:
        return 2
    elif tosdscp < 0 or tosdscp > 2**6-1:
        return 3
    elif totallength < 0 or totallength > 2**16-1:
        return 4
    elif identification < 0 or identification > 2**16-1:
        return 5
    elif flags < 0 or flags > 2**3-1:
        return 6
    elif fragmentoffset < 0 or fragmentoffset > 2**13-1:
        return 7
    elif timetolive < 0 or timetolive > 2**8-1:
        return 8
    elif protocoltype < 0 or protocoltype > 2**8-1:
        return 9
    elif headerchecksum < 0 or headerchecksum > 2**16-1:
        return 10
    elif sourceaddress < 0 or sourceaddress > 2**32-1:
        return 11
    elif destinationaddress < 0 or destinationaddress > 2**32-1:
        return 12
    else:
        return bytearray((destinationaddress + (sourceaddress << 32) + (headerchecksum << 64) + (protocoltype << 80) + (timetolive << 88) + (fragmentoffset << 96) + (flags << 109) + (identification << 112) + (totallength << 128) + (tosdscp << 144) + (hdrlen << 152) + (version << 156)).to_bytes(20, "big"))
    
#print(composepacket(5,5,0,4000,24200,0,63,22,6,4711, 2190815565, 3232270145))
#print(composepacket(4,5,0,1500,24200,0,63,22,6,4711, 2190815565, 3232270145))
#print(composepacket(4,16,0,4000,24200,0,63,22,6,4711, 2190815565, 3232270145))
#print(composepacket(4,15,64,4000,24200,0,63,22,6,4711, 2190815565, 3232270145))
#print(composepacket(4,15,63,65535,65535,7,8191,255,255,65535, 4294967295, 4294967296))
#print(composepacket(4,5,0,1500,24200,0,63,22,6,4711, 2190815565, 3232270145)[8])

#Check that the packet at least includes a full IPv4 header (i.e. the packet length is at least the minimum length of an IPv4 header). Check that the version number field has the correct value 4.Check that the header checksum is correct ('Header Checksum' field).Check that the total packet length field is consistent with the amount of data you have ('Total length' field).
def basicpacketcheck (pkt):
    if len(pkt) < 20:
        return 1
    elif (pkt[0] >> 4) != 4:
        return 2
    X = ((pkt[0] << 8) | pkt[1]) + ((pkt[2] << 8) | pkt[3]) + ((pkt[4] << 8) | pkt[5]) + ((pkt[6] << 8) | pkt[7]) + ((pkt[8] << 8) | pkt[9]) + ((pkt[10] << 8) | pkt[11]) + ((pkt[12] << 8) | pkt[13]) + ((pkt[14] << 8) | pkt[15]) + ((pkt[16] << 8) | pkt[17]) + ((pkt[18] << 8) | pkt[19])
    while X > 0xFFFF:
        X0 = X & 0xFFFF
        X1 = X >> 16
        X = X0 + X1
    if X != 0xFFFF:
        return 3
    size = (pkt[2] << 8) | pkt[3]
    if len(pkt) != size:
        return 4
    else:
        return True
    
#print(basicpacketcheck(bytearray ([0x45, 0x0, 0x0, 0x1e, 0x4, 0xd2, 0x0, 0x0, 0x40, 0x6, 0x20, 0xb4, 0x12, 0x34, 0x56, 0x78, 0x98, 0x76, 0x54, 0x32, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])))
#print(basicpacketcheck(bytearray ([0x45, 0x0, 0x0, 0x1e, 0x16, 0x2e, 0x0, 0x0, 0x40, 0x6, 0xcd, 0x59, 0x66, 0x66, 0x44, 0x44, 0x98, 0x76, 0x54, 0x32, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])))
#print(basicpacketcheck(bytearray ([0x45, 0x0, 0x0, 0x1b, 0x12, 0x67, 0x20, 0xe, 0x20, 0x6, 0x35, 0x58, 0x66, 0x66, 0x44, 0x44, 0x55, 0x44, 0x33, 0x22, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0])))

#extracts the IPv4 destination address from the received packet (which will be given to you as a bytearray) and which returns a pair (a, dd), where 'a' is the 32-bit value of the destination address, and 'dd' is a string showing the packet address in the so-called "dotted decimal notation"
def destaddress (pkt):
    addr = ((pkt[16] << 24) | (pkt[17] << 16) | (pkt[18] << 8) | pkt[19])
    dd = "{}.{}.{}.{}".format(pkt[16], pkt[17], pkt[18], pkt[19])
    return addr, dd    
#print(destaddress(bytearray(b'E\x00\x00\x1e\x04\xd2\x00\x00@\x06\x00\x00\x00\x124V3DUf')))

#returns the actual payload (and only the payload!) of a packet as a bytearray.
def payload (pkt):
    hdrlen = pkt[0] & 0xF
    actualLength = hdrlen * 4
    return pkt[actualLength:]    
#print(payload(bytearray(b'E\x00\x00\x17\x00\x00\x00\x00@\x06i\x8d\x11"3DUfw\x88\x10\x11\x12')))

#return either: an error code, i.e. an integer specifying a particular error in the parameters handed to the function, or a bytearray containing the entire IPv4 packet (header, payload), which is only to be returned when all validity checks have passed. When an extended header is required (i.e. when the 'hdrlen' parameter is greater than 5) then the additional 32-bit words making up the header options should be filled with zero bytes. Note that the IPv4 header contains two 'unused' bits, these have to be set to zero.
def revisedcompose (hdrlen, tosdscp, identification, flags, fragmentoffset, timetolive, protocoltype, sourceaddress, destinationaddress, payload):
    totallength = (hdrlen * 4) + len(payload)
    if hdrlen < 5 or hdrlen > 2**4-1:
        return 2
    elif tosdscp > 2**6-1 or tosdscp < 0:
        return 3
    elif totallength > 2**16-1 or totallength < 0:
        return 4
    elif identification > 2**16-1 or identification < 0:
        return 5
    elif flags > 2**3-1 or flags < 0:
        return 6
    elif fragmentoffset > 2**13-1 or fragmentoffset < 0:
        return 7
    elif timetolive > 2**8-1 or timetolive < 0:
        return 8
    elif protocoltype > 2**8-1 or protocoltype < 0:
        return 9
    version = 4
    emptybytes = (hdrlen * 4) - 20
    empty = emptybytes * 8    
    headerchecksum = 0
    N = hdrlen*4
    pkt = bytearray(((destinationaddress << empty) + (sourceaddress << (32 + empty)) + (headerchecksum << (64 + empty)) + (protocoltype << (80 + empty)) + (timetolive << (88 + empty)) + (fragmentoffset << (96 + empty)) + (flags << (109 + empty)) + (identification << (112 + empty)) + (totallength << (128 + empty)) + (tosdscp << (144 + empty)) + (hdrlen << (152 + empty)) + (version << (156 + empty))).to_bytes(hdrlen*4, "big"))    
    X = 0
    count = 0
    while count < N-4:
        X += ((pkt[count] << 8) | pkt[count + 1])
        count += 2
    while X > 0xFFFF:
        X0 = X & 0xFFFF
        X1 = X >> 16
        X = X0 + X1       
    headerchecksum = ~X & 0xFFFF
    if headerchecksum > 2**16-1 or headerchecksum < 0:
        return 10
    elif sourceaddress > 2**32-1 or sourceaddress < 0:
        return 11
    elif destinationaddress > 2**32-1 or destinationaddress < 0:
        return 12
    else:
        return bytearray(((destinationaddress << empty) + (sourceaddress << (32 + empty)) + (headerchecksum << (64 + empty)) + (protocoltype << (80 + empty)) + (timetolive << (88 + empty)) + (fragmentoffset << (96 + empty)) + (flags << (109 + empty)) + (identification << (112 + empty)) + (totallength << (128 + empty)) + (tosdscp << (144 + empty)) + (hdrlen << (152)) + (version << (156 + empty))).to_bytes(hdrlen*4, "big") + payload)

#print(revisedcompose (6, 24, 4711, 0, 22, 64, 0x06, 0x22334455, 0x66778899, bytearray([0x10, 0x11, 0x12, 0x13, 0x14, 0x15])))
#print(revisedcompose (5, 24, 4711, 0, 22, 64, 0x06, 0x22334455, 0x66778899, bytearray([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])))
#print(revisedcompose (5, 24, 4711, 0, 22, 64, 0x06, 0x66778899, 0x22334455, bytearray([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17])))

"""
Sender side simulation of RDT 3.0;

Input packets are formatted
[type, seq_num, message]
0 message with seq_num to be send;
1 ACK received; acking seq_num;
2 timeout event; resend last packet; 

Output packets are formatted
[status, seq_num]
-1 unexpected packet, -1 as seq_num;
0 message sent successfully, seq_num is the seq # of the message;
1 ACK processed; seq_num is the ACk seq_num;
2 resending finished; seq_num is the seq_num of the resent message;

Four states as described in the FSM
0 - wait for data 0;
1 - wait for ack 0;
2 - wait for data 1;
3 - wait for ack 1;

"""

def RDT_sender(event,state):        
    #Adding your own code below
    if len(event) >= 2:
        type_data, seq_num = event[0], event[1]
        if state == 0: #initial state; only accepts data 0; return error otherwise;
            if type_data == 0 and seq_num == 0:
                return 1, [0, seq_num]
            else:
                return state, [-1, -1]
        elif state == 1:
            if type_data == 1 and seq_num == 0:
                return 2, [1, seq_num]
            elif type_data == 2:
                return state, [2, seq_num]
            else:
                return state, [-1, -1]
        elif state == 2:
            if type_data == 0 and seq_num == 1:
                return 3, [0, seq_num]
            elif type_data == 2:
                return state, [2, seq_num]            
            else:
                return state, [-1, -1]
        elif state == 3:
            if type_data == 1 and seq_num == 1:
                return 0, [1, seq_num]
            elif type_data == 2:
                return state, [2, seq_num]
            else:
                return state, [-1, -1]
    else:
        return state, [2, 1] 
                
                                

#Do not modify the following lines    
def sndr_test(event_list):    
    state = 0
    action_list = []    
    
    for event in event_list:        
        state, action = RDT_sender(event,state)
        action_list.append(action)    
    print(f'{action_list}')
    
#sndr_test([[0, 0, 1], [2, 0, 1]])
#sndr_test([[0, 0, 1], [1, 0, 1], [0, 1, 3], [2],[1,1,3]])
#sndr_test([[0, 0, 1], [1, 0], [0, 1, 3], [1, 1]])
#sndr_test([[0, 0, 1], [1, 1, 1], [0, 1, 3], [1, 1, 3]])


def RDT_Receiver(packet):
    #Your code here:
    seq_num, data = packet
    if seq_num == 1 or seq_num == 0:
        return [0, seq_num]
    else:
        return [-1, -1]
    
    

#Do NOT modify the following lines    
def rcvr_test(packet_list):    
    action_list = []    
    
    for packet in packet_list:        
        action = RDT_Receiver(packet)
        action_list.append(action)    
        
    print(f'{action_list}')  
    
#rcvr_test([[0, 1]])

"""
Sender side simulation of GBN;

An event is formatted as
[type, seq_num, data]
0 data to send; no check on seq_num and data;
1 ACK received; acking seq_num;
2 timeout event; resend all outgoing unAck'ed events; no check on seq_num and data;

Output of function GBN_sender() is formatted as
[status, base, next_seq]
-1 unexpected event/window full
0 data sent successfully
1 ACK processed; 
2 resending finished; 

N - the window size
base - seq# of lower winder boundary (base)

"""

N = 4 #window size;

def GBN_sender(event,base,next_seq):
    if event[0] == 0: #Data to send; check whether the window is full;
        #Your code here
        if next_seq < N:
            return [0, base, next_seq+1]
        if base == N-1:
            return [0, base, next_seq+1]
        else:
            return [-1, base, next_seq]

    if event[0] == 1: #ACK to process;
        #Your code here
        if base <= event[1] <= next_seq-1:
            return [1, event[1]+1, next_seq]
        else:
            return [-1, base, next_seq]
        
    if event[0] == 2:#timeout event
        #Your code here
        return [2, base, next_seq]
                

#Do NOT modify the following code    
def sndr_test(event_list):    
    base = 0
    next_seq = 0
    action_list = []    
    
    for event in event_list:        
        action = GBN_sender(event,base,next_seq)
        base = action[1]
        next_seq = action[2]
        action_list.append(action)    
        
    print(f'{action_list}')
    
#sndr_test([[2,0,0]])
#sndr_test([[0, 0, 1]])
#sndr_test([[0, 0, 1], [0, 1, 2]])
#sndr_test([[0, 0, 1], [0, 1, 2], [0, 2, 3]])
#sndr_test([[0, 0, 1], [0, 1, 2], [0, 2, 3], [0, 3, 4], [0, 4, 5]])
#sndr_test([[0, 0, 1], [0, 1, 1], [1, 1, 3], [0, 1, 4]])
#sndr_test([[0, 0, 1], [0, 1, 1], [1, 1, 3], [0, 1, 4]])
#sndr_test([[0, 0, 1], [0, 1, 1], [1, 1, 3],[1,1,3]])
#sndr_test([[0, 0, 1], [0, 1, 2], [0, 2, 3], [0, 3, 4], [0, 4, 5], [1,2,3],[0,4,5],[0,5,6],[2,0,0],[1,4,5]])

"""
This is a program simulating the receiver side of GBN,
******************
Input packets are formatted as
[seq_num, data]

Output packets are formatted as
[status, exp_num]
0 - an ACK is sent;
-1 - unexpected packets received; 
*******************
"""

def GBN_Receiver(packet,exp_num):
    #Your code here
    seq_num, data = packet
    if seq_num == exp_num:
        return [0, exp_num+1]
    else:
        return [-1, exp_num]

           
#Do NOT modify the following code    
def rcvr_test(packet_list):    
    action_list = []
    exp_num = 1
    
    for packet in packet_list:        
        action = GBN_Receiver(packet,exp_num)
        exp_num = action[1]
        action_list.append(action)    
        
    print(f'{action_list}')
    
#rcvr_test([[1,1]])
#rcvr_test([[1,1],[2,2]])
#rcvr_test([[1,1],[2,2],[3,3]])
#rcvr_test([[0,1]])