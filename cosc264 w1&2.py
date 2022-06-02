# takes two parameters: an unsigned integer x (for Python: an integer x >= 0) and a positive integer base. find the coefficients for the number x in the given base, as integer values. Find only as many coefficients as are needed and collect them in a result list, with the highest-order coefficient being the first element, the second-highest-order coefficient being the second element, and so forth. Return the list of coefficients.
def convert (x, base):
    if type(x) != int:
        return -1
    elif type(base) != int:
        return -2
    elif x < 0:
        return -3
    elif base < 2:
        return -4
    else:
        result = []
        while x != 0:
            ans = x % base
            x = x // base
            result.append(ans)
        result.reverse()
        return result
    
#print (convert(1234, 10))
#print (convert(4660, 16))

#convert an unsigned integer x (in Python: a non-negative integer) into a string representing the hexadecimal representation of x. The string should be prepended with '0x'. Use 'A', 'B', .., 'F' for the literals greater than or equal to ten.        
def hexstring (x):
    if type(x) != int:
        return -1
    elif x < 0:
        return -2
    else:
        string = "0x"
        ans = convert(x,16)
        for answer in ans:
            if answer < 10:
                add = str(answer)
            else:
                if answer == 10:
                    add = 'A'
                elif answer == 11:
                    add = 'B'
                elif answer == 12:
                    add = 'C'
                elif answer == 13:
                    add = 'D'
                elif answer == 14:
                    add = 'E'
                elif answer == 15:
                    add = 'F'
            string += add
    return string

#print(hexstring(1234))

#takes a 32-bit number x and extracts the month, day and year fields, and which returns the given date as a string in the following format: 'dd.mm.yyyy', 
def decodedate (x):
    month = ((x & 0xF0000000) >> 28) + 1
    day = ((x & 0xF800000) >> 23) + 1
    year = (x & 0x7FFFFF)
    return '{}.{}.{}'.format(day,month,year)
#print(decodedate(1107298273))

#takes three values as parameters (one for day, one for month, one for year), checks them for the right ranges, and produces a 32-bit encoded value 
def encodedate (day, month, year):
    if day <= 0 or day > 31 or month <= 0 or month > 12 or year > ((2**23) - 1) or year < 0:
        return -1
    shiftmonth = (month-1) << 28
    shiftday = (day-1) << 23
    x = year | shiftday
    y = (x & 0x0FFFFFFF) | shiftmonth
    return y
#print(encodedate(5,5,2017))

#data rate is given by R Mbps and we are given a packet of length L bytes. How long does the transmission of this packet take
def transmission_delay (packetLength_bytes, rate_mbps):
    return (packetLength_bytes*8) / (rate_mbps*1000000)
print ("{:.6f}".format(transmission_delay(1500, 5)))

def transmission_delay (packetLength_bytes, rate_bps):
    return (packetLength_bytes*8) / rate_bps
#print ("{:.3f}".format(transmission_delay(1000000, 4000000)))

#calculate the total time between the instant where the transmitter starts with transmitting the first bit and the instant where the receiver has just completed the reception of the last bit.
def total_time (cableLength_KM, packetLength_b):
    rate_bps = 10000000000
    delay1 = packetLength_b / rate_bps
    delay2 = cableLength_KM / 200000
    delay = delay1 + delay2
    return delay * 1000    
#print ("{:.4f}".format(total_time(10000, 8000)))

#waiting time between entering the output line card and finishing the transmission of all previous packets is called the queueing delay
def queueing_delay (rate_bps, numPackets, packetLength_b):
    return (numPackets * packetLength_b) / rate_bps
#print ("{:.3f}".format(queueing_delay(100000000, 20, 1500)))

#average number of packet transmission trials that the transmitter has to make when the packet loss probability is P in (0,1)?
def average_trials (P):
    return (1 - P) ** - 1
#print ("{:.3f}".format(average_trials(0.2)))

#resulting probability that a packet of L bits is erroneous (i.e. has at least one flipped bit)
def per_from_ber (bitErrorProb, packetLen_b):
    error = 1 - ((1 - bitErrorProb) ** packetLen_b)
    return error
#print (per_from_ber(0.0001, 2000))

#average number of transmission trials in terms of the packet length L (in bits) and the bit error probability P
def avg_trials_from_ber (bit_error_probability, packetLength_b):
    error = 1 - ((1 - bit_error_probability) ** packetLength_b)
    avg = (1 - error) ** - 1
    return avg    
#print ("{:.3f}".format(avg_trials_from_ber(0.005, 1000)))

def queueingDelay (packetSize_bits, dataRate_bps, flagCurrentTransmission, numberInQueue):
    L    =  packetSize_bits
    R    =  dataRate_bps
    flag =  flagCurrentTransmission
    N    =  numberInQueue
    if flag is True:
        return (L * N) / R
    else:
        return L / R
print(abs(queueingDelay(1000,1000000,True,0)-0.0005)<0.00001)
print(abs(queueingDelay(1000,1000000,False,0)-0.0000)<0.00001)