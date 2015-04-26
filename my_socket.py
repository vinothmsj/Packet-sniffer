import socket
import sys
from time import gmtime, strftime
from struct import * 

#function returns the mac address format 
def ethernet_address_format(a):
	return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
# Returns apt message for icmp type 
def icmp_messages(icmp_type):
	icmp_type_dict={0:'Echo Reply',3:'Destination Unreachable',11:'Time exceeded'}
	return icmp_type_dict.get(icmp_type)
#Returns apt message for igmp type 
def igmp_messages(igmp_type):
	igmp_type_dict={1:'Create Group Request',2:'Create Group Reply', 3:'Join Group Request',4:'Join Group Reply',5:'Leave Group Request',6:'Leave Group Reply',7:'Confirm Group Request', 8: 'Confirm Group Reply'}
	return igmp_type_dict.get(igmp_type)

# from the ethernet packet we get ip  details such source, dest address and protocl type 	
def protocol_capture(eth_protocol,content):
 
	if eth_protocol==8:
		ip_data=content[14:34]
		ip_unpack=unpack('!BBHHHBBH4s4s',ip_data)
		source_ip=socket.inet_ntoa(ip_unpack[8]);
		destination_ip=socket.inet_ntoa(ip_unpack[9])
		ip_version=ip_unpack[0]
		ip_version_data=ip_version >> 4
		if ip_version_data==4:
			ip_length=20
		else:
			ip_length=40
		
		ip_protocol=ip_unpack[6]
		print 'IP_DATA:  ' + ' Source Ip : ' + str(source_ip) + ' Destination Ip: ' + destination_ip + ' Ip_version: ' + str(ip_version_data) + ' Ip_protocol:' + str(ip_protocol)+ ' Ip Header length ' + str(ip_version_data) 

#Based on the protocol we will separate TCP, UDP, ICMP packets Below the logic for the getting the detilsin TCP packet.
#This is when the ip_protocol is 6
		if ip_protocol==6:
			tcp_length=ip_length+14;
			tcp_data=content[tcp_length:tcp_length+20]
			tcp_unpack=unpack('!HHLLBBHHH' , tcp_data)
			tcp_sourceport=tcp_unpack[0]
			tcp_destport=tcp_unpack[1]
			tcp_sequence=tcp_unpack[2]
			tcp_ack=tcp_unpack[3]
			doff_reserved=tcp_unpack[4]
			tcp_head_length=doff_reserved >> 4		
			print 'TCP_DATA:' + ' Source Port :' + str(tcp_sourceport) + ' Destination Port:' + str(tcp_destport) + ' Sequence:' +str(tcp_sequence)+ ' Acknowledgement:' + str(tcp_ack)

#Now when the ip_protocol value equals 1 it is a ICMP packet

		elif ip_protocol==1:
			icmp_length=ip_length+14
			icmp_data=content[icmp_length:icmp_length+4]
			icmp_unpack=unpack('!BBH' ,icmp_data)
			icmp_type=icmp_unpack[0]
			icmp_code=icmp_unpack[1]
			icmp_checksum=icmp_unpack[2]
			message=icmp_messages(icmp_type)
			print 'ICMP_DATA:' +' Icmp_type ' + str(icmp_type) + ' Icmp_code ' + str(icmp_code) + ' Icmp_checksum ' + str(icmp_checksum)+' Icmp Message: ' + str(message)


#When the ip_protocol value equal 17 it is a UDP packet and below are UDP details

		elif ip_protocol==17:
			udp_length=ip_length+14
			udp_data=content[udp_length:udp_length+8]
			udp_unpack=unpack('!HHHH' , udp_data)
			udp_source=udp_unpack[0]
			udp_destination=udp_unpack[1]
			udp_checksum=udp_unpack[3]	
			print 'UDP DATA:' + ' Source port: '  + str(udp_source) + ' Destination port: ' + str(udp_destination) + ' Check Sum ' + str(udp_checksum)
# if the ip_protocl is 2 then it is a IGMP packet
		elif ip_protocol==2:
			igmp_length=ip_length+14
			igmp_data=content[igmp_length:igmp_length+4]
			igmp_unpack=unpack('!BBHHHBBH4s4sI',igmp_data)
			igmp_type=igmp_unpack[0]
			igmp_code=igmp_unpack[1]
			igmp_checksum=igmp_unpack[3]
			message=igmp_meessages(igmp_type)
			print 'IGMP_DATA:' + 'Igmp Type:' + str(igmp_type)+' Igmp_code' + str(igmp_code) +' igmp checksum' + igmp_checksum+' Igmp message: ' + message
		return True 
		
def socket_definition():
#Socket definition to sniff incoming and outgoing traffic.. All Ethernet frames , which means all kinds of IP packets(TCP , UDP , ICMP) and even other kinds of packets(like ARP) if there are any. It will also provide the ethernet header as a part of the received packet.
	try:
		s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x0003))
		print "Socket created"
	except socket.error,msg: print "Socket not available"
	while True:
		data_packet=s.recvfrom(65656)
		content=data_packet[0]
		ethernet_data=content[0:14]
		ethernet_unpack=unpack('!6s6sH',ethernet_data)
		destination_mac=ethernet_address_format(content[0:6])
		source_mac=ethernet_address_format(content[6:12])
		eth_protocol=socket.ntohs(ethernet_unpack[2])	
		print ' ---------------------------------------------------------------------------------'
		print 'TIME: ' + strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime())
		print 'ETHERNET_DATA:'+' Destination Mac:' + destination_mac + 'Source Mac: ' + source_mac + ' Protocol: ' + str(eth_protocol)
		protocol_capture(eth_protocol,content)	
	

socket_definition()

