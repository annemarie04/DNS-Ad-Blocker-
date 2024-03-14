# https://github.com/0xTony/DNS-Ad-Blocker -> Regex list, check for www. in host, check for subdomains
# https://www.geeksforgeeks.org/network-programming-in-python-dns-look-up/ -> dns.resolver
import socket
from scapy.all import DNS, DNSRR, DNSQR, IP, sr1, UDP, send, sniff, Raw, TCP, PSH
import multiprocessing
from multiprocessing import Process, Lock
import asyncio
import re
import dns.resolver

# dig sends UDP packets to port 53 by default
# So we need to listen on port 53
# DNS works on port 53 by default

# Our IP so we can receive packets
# 127.0.0.1 localhost
RegExList = "^(ad|ads|-ad|-ads|advert|counter|counters|stats|track|tracker|tracking)\d*\.|\S(.adspace|.adspot|.adtech|advertisement|.ad-cloud|.ad-sys|.ad-traffic|.stats)\S*\.|\.(zip|review|country|kim|cricket|science|work|party|gq|link)$"

listenAddress = ['0.0.0.0', 53]
dnsAdress = ['8.8.8.8', 53]
filename = "blacklist.txt"

# BlockListDict is a pair, host and count blocked
# Initially, count = 0
BlockListDict = {}

# check if the host needs to be blocked.
# return True is needs blocking - else False is ok
def checkBlackList(queryName):
     for key in BlockListDict.keys():
          if key.strip('\n') == queryName:
               return True
     return False

def isBlocked(host):
	# strip any www. from the url because the blocklist removed them all
	# TODO, make sure its not www.com ittr = host.count('.') 
	if host.startswith("www."):
		host = host.replace("www.", "") # no longer in host files
	
	# Need to check regex and block cache for all requests no matter what. 
	if (checkCache(host)): 
		return True
	if (checkRegEx(host)):
		return True
	return False

def checkRegEx(host):
	if re.match(RegExList, host):
		print("Blocking Regex " + host)
		BlockListDict[host] = 0
		rwrite.write( host)
		return True
	return False
	
# Check the host, and progressively strip the left part of the URL looking for a subdomain match
def checkCache(host):
	ittr = host.count('.') # how far do we go 
	# check if ittr is too high, if so bail because it bogus
	if ittr > 10: return True # more then 10 dots in the request address is bogus, fail.
	while ittr > 0:
		if BlockListDict.get(host) is not None:
			print("URL in list " + host)
			return True
		temp, host = host.split('.', 1)
		ittr = ittr - 1
	return False

# DNS Query with scapy
def DNSQuery(queryName):
    # DNS request către google DNS
    ip = IP(dst = dnsAdress[0])
    transport = UDP(sport = RandShort(), dport = 53)

    # rd = 1 cod de request
    dns = DNS(rd = 1)

    # query pentru a afla entry de tipul 
    dns_query = DNSQR(qname = queryName, qtype = "A")
    dns.qd = dns_query
    response = sr1(ip / transport / dns, verbose=1, timeout=1)
    print("QUEEEEEERYYYYYYYY")
    print(queryName.strip(".\n"))
    if isBlocked(queryName.strip('\n')):
        print("Add Detected!")
        return '0.0.0.0'
    else:
        try:
            if type(response.an.rdata) is not bytes:
                print('------------')
                print(response.an.rdata)
                print('------------')
                return response.an.rdata
            else:
                 return '0.0.0.0'
        except:
            return '0.0.0.0'
        
# DNS Query with dns.resolver
def DNSQuery2(queryName):

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '193.231.252.1', '213.154.124.1']
    answer = resolver.resolve(queryName, "A")
    if len(answer) == 0:
        return '0.0.0.0'
    else:
        return str(answer[0])


def readFile(filename):
	target = open(filename, 'r')
	data = target.read()
	target.close()
	return data

def loadBlockList(filename):
    i = 0
    data = readFile(filename)
        
    for line in data.split('\n'): # Simple checking for hostname match
        element = line.split(" ")
        domain = element[1].strip()
        BlockListDict[str(domain)] = 0
        i = i + 1
    
    print("Loaded " + str(i) + " domains to block list")

def clientHandler(client_socket):

    while True:
        try:
            # listen for requests infinitely
            request, source_address = client_socket.recvfrom(1024)

            # Converting the Payload to a Scapy Packet
            packet = DNS(request)
            dns = packet.getlayer(DNS)

            # Check if the packet is a DNS Query
            if dns is not None and dns.opcode == 0: # DNS QUERY

                # Check if query is for a blocked domain
                domainName = dns.qd.qname.decode('utf-8')
                key = domainName.strip('.')

                if isBlocked(key.strip('\n')):
                    print("Add Detected!")
                    fwrite.write(str(key) + '\n')
                    fwrite.flush()
                    rrdata = '0.0.0.0'
                else:
                    # Handle DNS Query
                    print(str(key))
                    # 
                    
                    rrdata = DNSQuery2(key)

                # Build DNS Response
                if rrdata is None:
                    continue
                dns_answer = DNSRR(      # DNS Reply
                rrname = dns.qd.qname, # for question
                ttl = 330,             # DNS entry Time to Live
                type = "A",            
                rclass = "IN",
                rdata = rrdata)     # found at IP: scapyIP :)
                dns_response = DNS(
                        id = packet[DNS].id, # DNS replies must have the same ID as requests
                        qr = 1,              # 1 for response, 0 for query 
                        aa = 0,              # Authoritative Answer
                        rcode = 0,           # 0, nicio eroare http://www.networksorcery.com/enp/protocol/dns.htm#Rcode,%20Return%20code
                        qd = packet.qd,      # request-ul original
                        an = dns_answer)     # obiectul de reply
                
                # Send DNS Response
                client_socket.sendto(bytes(dns_response), source_address)
                    
        except Exception as e:
            print("Error! on clientHandler, client_socket:" + str(e))


#################################################### Main ####################################################

if __name__ == "__main__":
    # Load blacklist of domains
    loadBlockList('adservers.txt')
    loadBlockList('facebook.txt')
    loadBlockList('coinMiner.txt')
    rwrite = open("regexblock", 'w')
    fwrite = open("blocked.txt", 'w')
    good = open("notBlocked.txt", 'w')

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)   
    # AF_INET = we want to send data using IPv4
    # SOCK_DGRAM = we want to send data using UDP instead of TCP

    # Bind the ip and port to the socket 
    try:
        client_socket.bind((listenAddress[0], listenAddress[1]))
    except socket.error as err:
        print("Couldn't bind server on %r" % (listenAddress, ))
        raise SystemExit

    clientHandler(client_socket)
    client_socket.close()



