#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>


#include <netdb.h>
#include <ifaddrs.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>

#include <linux/wireless.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

//see https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
//see https://en.wikipedia.org/wiki/Escape_sequences_in_C
//see https://en.wikipedia.org/wiki/ANSI_escape_code
#define RED(string)     "\x1b[31m" string "\x1b[0m"
#define GREY(string)   "\x1b[90m" string "\x1b[0m"
#define YELLOW(string)  "\x1b[33m" string "\x1b[0m"
#define BLUE(string)    "\x1b[34m" string "\x1b[0m"
#define MAGENTA(string) "\x1b[35m" string "\x1b[0m"
#define CYAN(string)    "\x1b[36m" string "\x1b[0m"
#define GREEN(string)   "\x1b[32m" string "\x1b[0m"


#define BUFFER_SIZE 65536
unsigned char* buffer;
int sockfd;
//see man 7 netdevice
/*
struct ifreq{
   char ifr_name[IFNAMSIZ];  // Interface name 
   union {
      struct sockaddr ifr_addr;
      struct sockaddr ifr_dstaddr;
      struct sockaddr ifr_broadaddr;
      struct sockaddr ifr_netmask;
      struct sockaddr ifr_hwaddr;
      short           ifr_flags;
      int             ifr_ifindex;
      int             ifr_metric;
      int             ifr_mtu;
      struct ifmap    ifr_map;
      char            ifr_slave[IFNAMSIZ];
      char            ifr_newname[IFNAMSIZ];
      char           *ifr_data;
   };
};
*/
struct ifreq ifreq;
/*
struct sockaddr_ll
{
        unsigned short       sll_family;
        __be16               sll_protocol;
        int                  sll_ifindex;
        unsigned short       sll_hatype;
        unsigned char        sll_pkttype;
        unsigned char        sll_halen;
        unsigned char        sll_addr[8];
};
*/
struct sockaddr_ll sll;
//man 2 socket
//int socket(int domain, int type, int protocol);
//domain: AF_PACKET Low-level packet interface packet(7)
//The socket_type is SOCK_RAW for raw  packets  including  the  link-level  header  
void InitSocket(){
   //for ETH_P_ALL 
   //see man 7 packet dsecription sec para
   //When protocol is set to htons(ETH_P_ALL), then all protocols are
   //received.  All incoming packets of that protocol type will be
   //passed to the packet socket before they are passed to the
   //protocols implemented in the kernel.
   sockfd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
   if(sockfd<0){
      fprintf(stderr,RED("SOCKET::ERROR:") "%s\n",strerror(errno));
      exit(EXIT_FAILURE);
   }
   fprintf(stdout,GREY(">SOCKET CREATE SUCCESSFULLY") "\n");
}

void InitInterface(char* name){
   buffer=calloc(BUFFER_SIZE,sizeof(unsigned char));
   memset(&ifreq,0,sizeof(ifreq));
   strncpy((char*)ifreq.ifr_name,name,IFNAMSIZ);
   if(ioctl(sockfd,SIOCGIFCONF,&ifreq)<0){
     fprintf(stderr,RED("IOCTL::ERROR:") "%s\n",strerror(errno));
     exit(EXIT_FAILURE);
   }
   fprintf(stdout,GREY(">IOCT SUCCESS") "\n");
   bzero(&sll,sizeof(sll));
   sll.sll_family=AF_PACKET;
   sll.sll_ifindex=ifreq.ifr_ifindex;
   sll.sll_protocol=htons(ETH_P_ALL);
}

//man 2 bind
//int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
void Bind(){
  if(bind(sockfd,(struct sockaddr *)&sll,sizeof(sll))<0){
     fprintf(stderr,RED(">BIND::ERROR:") "%s\n",strerror(errno));
     exit(EXIT_FAILURE);
  }
  fprintf(stdout,GREY(">BIND SUCCESS") "\n"); 
}

void HexDump(char* mesg,unsigned char* p,int len){
   fprintf(stdout,"%s",mesg);
   int i=0;
   printf("\n");
   while(i<len){
      fprintf(stdout,"%08X ",i);
      for(int j=i;j<i+16;j++){
         fprintf(stdout,"%02X ",p[j]);
      }
      fprintf(stdout,"|");
      for(int j=0;j<i+16;j++){
         if(isprint(p[j])) fprintf(stdout,"%c",p[j]);
	 else fprintf(stdout,".");
      }
      fprintf(stdout,"|\n");
      i+=16;
   }
}

//Memory Layout
//Layer 1 Physical Layer not relate dto this project
//Layer 2 Data Link struct ethhdr
//Layer 3 Network struct iphdr
//Layer 4 Transport struct tcphdr\udphdr
//Layer 5 Payload Data buffer+ethhdr+iphdr+tcphdr

/* see https://github.com/torvalds/linux/blob/master/include/uapi/linux/udp.h
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};
*/
void PrintUdpPacket(unsigned char* buffer,int len){
   //Layer 4 so rthhdr+iphdr
   struct udphdr* udphdr=(struct udphdr*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
   if(len<sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(udphdr)){
      fprintf(stderr,RED("INVALID CAPTURE\n"));
   }
   else{
      fprintf(stdout,BLUE("UDP PACKET\n"));
      // The  ntohs()  function converts the unsigned short integer netshort from network byte order
      //to host byte order.
      //see man ntohs
      fprintf(stdout,BLUE("UDP SOURCE:") "%u\n",ntohs(udphdr->source));
      fprintf(stdout,BLUE("UDP DEST:") "%u\n",ntohs(udphdr->dest));
      fprintf(stdout,BLUE("UDP LEN:") "%u\n",ntohs(udphdr->len));
      fprintf(stdout,BLUE("UDP CHECKSUM:") "%u\n",ntohs(udphdr->check));
      HexDump(MAGENTA("UDP PAYLOAD"),
	      (unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(udphdr)),
	      len
	     );
   }
}

/*see https://github.com/torvalds/linux/blob/master/include/uapi/linux/tcp.h 
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	ae:1,
		res1:3,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:3,
		ae:1,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
*/

void PrintTcpPacket(unsigned char* buffer,int len){
   //layer 4 so same as udphdr
   struct tcphdr* tcphdr=(struct tcphdr*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
   if(len<sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(tcphdr)){
       fprintf(stderr,RED("INVALID CAPTURE\n"));
   }
   else{
      fprintf(stdout,YELLOW("TCP PACKET\n"));
      fprintf(stdout,YELLOW("TCP SOURCE:") "%u\n",ntohs(tcphdr->source));
      fprintf(stdout,YELLOW("TCP DEST:") "%u\n",ntohs(tcphdr->dest));
      fprintf(stdout,YELLOW("TCP SEQ:") "%u\n",ntohl(tcphdr->seq));
      fprintf(stdout,YELLOW("TCP ACK SEQ:") "%u\n",ntohl(tcphdr->ack_seq));
      //doff data offset
      //Data Offset (4-byte units); header is doff*4 bytes long
      //see https://www.cs.auckland.ac.nz/~nevil/pypy-libtrace/TCP.html
      fprintf(stdout,YELLOW("TCP HEDAER LEN:") "%u bytes\n",tcphdr->doff*4);
      //cwr Congestion Window Reduced
      //ece ECN-Echo
      //see https://www.catchpoint.com/blog/ece-cwr-tcp
      //see https://www.geeksforgeeks.org/computer-networks/working-of-explicit-congestion-notification/
      fprintf(stdout,YELLOW("TCP CWR FLAG:") "%d\n",tcphdr->cwr);
      fprintf(stdout,YELLOW("TCP ECE FLAG:") "%d\n",tcphdr->ece);
      //see https://litux.nl/mirror/securitytools/ddu/ch06lev1sec3.html table 6.1
      //URG Urgency pointer Indicates the TCP priority of the packets
      fprintf(stdout,YELLOW("TCP URG FLAG:") "%d\n",tcphdr->urg);
      //ACK Acknowledgment Designates this packet as an acknowledgment of receipt.
      fprintf(stdout,YELLOW("TCP ACK FLAG:") "%d\n",tcphdr->ack);
      //PSH Push Flushes queued data from buffers.
      fprintf(stdout,YELLOW("TCP PSH FLAG:") "%d\n",tcphdr->psh);
      //
      fprintf(stdout,YELLOW("TCP RST FLAG:") "%d\n",tcphdr->rst);
      //
      fprintf(stdout,YELLOW("TCP SYN FLAG:") "%d\n",tcphdr->syn);
      //
      fprintf(stdout,YELLOW("TCP FIN FLAG:") "%d\n",tcphdr->fin);
      fprintf(stdout,YELLOW("TCP WINDOW:") "%d\n",tcphdr->window);
      fprintf(stdout,YELLOW("TCP CHECKSUM") "%d\n",tcphdr->check);
      fprintf(stdout,"URGENT POINTER:%d\n",tcphdr->urg_ptr);
      HexDump(
         MAGENTA("TCP PAYLOAD"),
              (unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(tcphdr)),
              len
      );
   }
}


//see https://github.com/spotify/linux/blob/master/include/linux/icmp.h
/*
#define ICMP_ECHOREPLY		0	// Echo Reply			
#define ICMP_DEST_UNREACH	3	// Destination Unreachable	
#define ICMP_SOURCE_QUENCH	4	// Source Quench		
#define ICMP_REDIRECT		5	// Redirect (change route)	
#define ICMP_ECHO		8	// Echo Request			
#define ICMP_TIME_EXCEEDED	11	// Time Exceeded		
#define ICMP_PARAMETERPROB	12	// Parameter Problem		
#define ICMP_TIMESTAMP		13	// Timestamp Request		
#define ICMP_TIMESTAMPREPLY	14	// Timestamp Reply		
#define ICMP_INFO_REQUEST	15	// Information Request		
#define ICMP_INFO_REPLY		16	// Information Reply		
#define ICMP_ADDRESS		17	// Address Mask Request		
#define ICMP_ADDRESSREPLY	18	// Address Mask Reply		
*/

char* GET_ICMP_PROTO(unsigned int type){
   switch(type){
      case  ICMP_ECHOREPLY: return "Echo Reply";
      case  ICMP_DEST_UNREACH: return "Destination Unreachable";
      case  ICMP_SOURCE_QUENCH: return "Source Quench";
      case  ICMP_REDIRECT: return "Redirect (change route)";
      case  ICMP_ECHO: return "Echo Request";
      case  ICMP_TIME_EXCEEDED: return "Time Exceeded";
      case  ICMP_PARAMETERPROB: return "Parameter Problem";
      case  ICMP_TIMESTAMPREPLY: return "Timestamp Reply";
      case  ICMP_INFO_REQUEST: return "Information Request";
      case  ICMP_INFO_REPLY: return "Information Reply";
      case  ICMP_ADDRESS: return "Address Mask Request";
      case  ICMP_ADDRESSREPLY: return "Address Mask Reply";
      default: return "Unknown";
   }
}

//see https://github.com/spotify/linux/blob/master/include/linux/icmp.h
/*
struct icmphdr {
  __u8		type;
  __u8		code;
  __sum16	checksum;
  union {
	struct {
		__be16	id;
		__be16	sequence;
	} echo;
	__be32	gateway;
	struct {
		__be16	__unused;
		__be16	mtu;
	} frag;
  } un;
};
*/
void PrintIcmpPacket(unsigned char* buffer,int len){
   //icmp layer 3 after ethhdr
   struct icmphdr *icmphdr=(struct icmphdr*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr));
   if(len<sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(icmphdr)){
       fprintf(stderr,RED("INVALID CAPTURE\n"));
   }
   else{
      fprintf(stdout,RED("ICMP\n"));
      fprintf(stdout,RED("ICMP TYPE:") " %d " " %s \n",icmphdr->type,GET_ICMP_PROTO((unsigned int)(icmphdr->type)));
      fprintf(stdout,RED("ICMP CODE;") "%d\n",icmphdr->code);
      fprintf(stdout,RED("ICMP CHECKSUM:") "%d\n",icmphdr->checksum);
      HexDump(
	      MAGENTA("ICMP Packet Dump"),
	      (unsigned char*)(buffer+sizeof(struct ethhdr)+sizeof(struct iphdr)),
	      len
	     );
   }
}

/* see https://github.com/torvalds/linux/blob/master/include/uapi/linux/in.h
enum {
  IPPROTO_IP = 0,		 Dummy protocol for TCP		
#define IPPROTO_IP		IPPROTO_IP
  IPPROTO_ICMP = 1,		// Internet Control Message Protocol	
#define IPPROTO_ICMP		IPPROTO_ICMP
  IPPROTO_IGMP = 2,		// Internet Group Management Protocol	
#define IPPROTO_IGMP		IPPROTO_IGMP
  IPPROTO_IPIP = 4,		// IPIP tunnels (older KA9Q tunnels use 94) 
#define IPPROTO_IPIP		IPPROTO_IPIP
  IPPROTO_TCP = 6,		// Transmission Control Protocol	
#define IPPROTO_TCP		IPPROTO_TCP
  IPPROTO_EGP = 8,		// Exterior Gateway Protocol		
#define IPPROTO_EGP		IPPROTO_EGP
  IPPROTO_PUP = 12,	MAGENTA	// PUP protocol				
#define IPPROTO_PUP		IPPROTO_PUP
  IPPROTO_UDP = 17,		// User Datagram Protocol		
#define IPPROTO_UDP		IPPROTO_UDP
  IPPROTO_IDP = 22,		// XNS IDP protocol			
#define IPPROTO_IDP		IPPROTO_IDP
  IPPROTO_TP = 29,		// SO Transport Protocol Class 4	
#define IPPROTO_TP		IPPROTO_TP
  IPPROTO_DCCP = 33,		// Datagram Congestion Control Protocol 
#define IPPROTO_DCCP		IPPROTO_DCCP
  IPPROTO_IPV6 = 41,		// IPv6-in-IPv4 tunnelling		
#define IPPROTO_IPV6		IPPROTO_IPV6
  IPPROTO_RSVP = 46,		// RSVP Protocol			
#define IPPROTO_RSVP		IPPROTO_RSVP
  IPPROTO_GRE = 47,		// Cisco GRE tunnels (rfc 1701,1702)	
#define IPPROTO_GRE		IPPROTO_GRE
  IPPROTO_ESP = 50,		// Encapsulation Security Payload protocol 
#define IPPROTO_ESP		IPPROTO_ESP
  IPPROTO_AH = 51,		// Authentication Header protocol	
#define IPPROTO_AH		IPPROTO_AH
  IPPROTO_MTP = 92,		// Multicast Transport Protocol		
#define IPPROTO_MTP		IPPROTO_MTP
  IPPROTO_BEETPH = 94,		// IP option pseudo header for BEET	
#define IPPROTO_BEETPH		IPPROTO_BEETPH
  IPPROTO_ENCAP = 98,		// Encapsulation Header			
#define IPPROTO_ENCAP		IPPROTO_ENCAP
  IPPROTO_PIM = 103,		// Protocol Independent Multicast	
#define IPPROTO_PIM		IPPROTO_PIM
  IPPROTO_COMP = 108,		// Compression Header Protocol		
#define IPPROTO_COMP		IPPROTO_COMP
  IPPROTO_L2TP = 115,		// Layer 2 Tunnelling Protocol		
#define IPPROTO_L2TP		IPPROTO_L2TP
  IPPROTO_SCTP = 132,		// Stream Control Transport Protocol	
#define IPPROTO_SCTP		IPPROTO_SCTP
  IPPROTO_UDPLITE = 136,	// UDP-Lite (RFC 3828)			
#define IPPROTO_UDPLITE		IPPROTO_UDPLITE
  IPPROTO_MPLS = 137,		// MPLS in IP (RFC 4023)		
#define IPPROTO_MPLS		IPPROTO_MPLS
  IPPROTO_ETHERNET = 143,	// Ethernet-within-IPv6 Encapsulation	
#define IPPROTO_ETHERNET	IPPROTO_ETHERNET
  IPPROTO_AGGFRAG = 144,	// AGGFRAG in ESP (RFC 9347)		
#define IPPROTO_AGGFRAG		IPPROTO_AGGFRAG
  IPPROTO_RAW = 255,		// Raw IP packets			
#define IPPROTO_RAW		IPPROTO_RAW
  IPPROTO_SMC = 256,		// Shared Memory Communications		
#define IPPROTO_SMC		IPPROTO_SMC
  IPPROTO_MPTCP = 262,		// Multipath TCP connection		
#define IPPROTO_MPTCP		IPPROTO_MPTCP
  IPPROTO_MAX
};
#endif
*/

char* GET_IP_PROTO(unsigned int proto){
   switch(proto){
      case IPPROTO_IP: return "Dummy protocol for TCP";
      case IPPROTO_ICMP: return "Internet Control Message Protocol";
      case IPPROTO_IGMP: return "Internet Group Management Protocol";
      case IPPROTO_IPIP: return "PIP tunnels (older KA9Q tunnels use 94)";
      case IPPROTO_TCP: return "Transmission Control Protocol";
      case IPPROTO_EGP: return "Exterior Gateway Protocol";
      case IPPROTO_PUP: return "PUP protocol";
      case IPPROTO_UDP: return "XNS IDP protocol";
      case IPPROTO_IDP: return "SO Transport Protocol Class 4";
      case IPPROTO_DCCP: return "Datagram Congestion Control Protocol";
      case IPPROTO_IPV6: return "IPv6-in-IPv4 tunnelling";
      case IPPROTO_RSVP: return "RSVP Protocol";
      case IPPROTO_GRE: return "Cisco GRE tunnels (rfc 1701,1702)";
      case IPPROTO_ESP: return "Encapsulation Security Payload protocol";
      case IPPROTO_AH: return "Authentication Header protocol";
      case IPPROTO_MTP: return "Multicast Transport Protocol";
      case IPPROTO_BEETPH: return "IP option pseudo header for BEET";
      case IPPROTO_ENCAP: return "Encapsulation Header";
      case IPPROTO_PIM: return "Protocol Independent Multicast";
      case IPPROTO_COMP: return "Compression Header Protocol";
      case IPPROTO_L2TP: return "Layer 2 Tunnelling Protocol";
      case IPPROTO_SCTP: return "Stream Control Transport Protocol";
      case IPPROTO_UDPLITE: return "UDP-Lite (RFC 3828)";
      case IPPROTO_MPLS: return "MPLS in IP (RFC 4023)";
      case IPPROTO_ETHERNET: return "Ethernet-within-IPv6 Encapsulation";
      case IPPROTO_RAW: return "Raw IP packets";
      case IPPROTO_SMC: return "Shared Memory Communications";
      case IPPROTO_MPTCP: return "Multipath TCP connection";
      default: return "Unknown Protocol";
   }
}

//see https://github.com/torvalds/linux/blob/master/include/uapi/linux/ip.h
/*
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__struct_group(// no tag , addrs,  no attrs ,
		__be32	saddr;
		__be32	daddr;
	);
	//The options start here. 
};
*/
unsigned int PrintIpPacket(unsigned char* buffer,int len){
   //iphdr layer 3 after ethhdr
   struct iphdr* iphdr=(struct iphdr*)(buffer+sizeof(struct ethhdr));
   struct sockaddr_in source,dest;
   bzero(&source,sizeof(source));
   source.sin_addr.s_addr=iphdr->saddr;
   dest.sin_addr.s_addr=iphdr->daddr;
   fprintf(stdout,MAGENTA("IP PACKET\n"));
   fprintf(stdout,MAGENTA("VERSION IPv:") "%d\n",iphdr->version);
   fprintf(stdout,MAGENTA("IP HEADER LEN:") "%d bytes\n",iphdr->ihl*4);
   fprintf(stdout,MAGENTA("TYPE OF SERVICE:") "%d\n",iphdr->tos);
   fprintf(stdout,MAGENTA("TOTAL LENGTH:") "%d\n",ntohs(iphdr->tot_len));
   fprintf(stdout,MAGENTA("ID:") "%d\n",ntohs(iphdr->id));
   fprintf(stdout,MAGENTA("TTL:") "%d\n",iphdr->ttl);
   fprintf(stdout,MAGENTA("PROTOCOL:") "%s\n",GET_IP_PROTO(iphdr->protocol));
   fprintf(stdout,MAGENTA("CHECKSUM:") "%d\n",ntohs(iphdr->check));
   fprintf(stdout,MAGENTA("SOURCE:") "%s\n",inet_ntoa(source.sin_addr));
   fprintf(stdout,MAGENTA("DEST:") "%s\n",inet_ntoa(dest.sin_addr));
   return (unsigned int)iphdr->protocol;
}


//https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h

const char *GET_ETH_PROTO(unsigned int proto)
{
    switch (proto) {
    case ETH_P_LOOP:       return "Ethernet Loopback packet";
    case ETH_P_PUP:        return "Xerox PUP packet";
    case ETH_P_PUPAT:      return "Xerox PUP Addr Trans packet";
    case ETH_P_TSN:        return "TSN (IEEE 1722) packet";
    case ETH_P_ERSPAN2:    return "ERSPAN version 2 (type III)";
    case ETH_P_IP:         return "Internet Protocol packet";
    case ETH_P_X25:        return "CCITT X.25";
    case ETH_P_ARP:        return "Address Resolution Protocol";
    case ETH_P_BPQ:        return "G8BPQ AX.25 Ethernet Packet";
    case ETH_P_IEEEPUP:    return "Xerox IEEE 802.3 PUP packet";
    case ETH_P_IEEEPUPAT:  return "Xerox IEEE 802.3 PUP Addr Trans packet";
    case ETH_P_BATMAN:     return "B.A.T.M.A.N.-Advanced packet";

    case ETH_P_DEC:        return "DEC Assigned protocol";
    case ETH_P_DNA_DL:     return "DEC DNA Dump/Load";
    case ETH_P_DNA_RC:     return "DEC DNA Remote Console";
    case ETH_P_DNA_RT:     return "DEC DNA Routing";
    case ETH_P_LAT:        return "DEC LAT";
    case ETH_P_DIAG:       return "DEC Diagnostics";
    case ETH_P_CUST:       return "DEC Customer use";
    case ETH_P_SCA:        return "DEC Systems Communication Architecture";

    case ETH_P_TEB:        return "Transparent Ethernet Bridging";
    case ETH_P_RARP:       return "Reverse Address Resolution Protocol";
    case ETH_P_ATALK:      return "AppleTalk DDP";
    case ETH_P_AARP:       return "AppleTalk AARP";
    case ETH_P_8021Q:      return "IEEE 802.1Q VLAN";
    case ETH_P_ERSPAN:     return "ERSPAN type II";
    case ETH_P_IPX:        return "IPX over DIX";
    case ETH_P_IPV6:       return "IPv6";
    case ETH_P_PAUSE:      return "IEEE 802.3 Pause frame";
    case ETH_P_SLOW:       return "IEEE 802.3ad Slow Protocol";
    case ETH_P_WCCP:       return "Web Cache Coordination Protocol";
    case ETH_P_MPLS_UC:    return "MPLS Unicast";
    case ETH_P_MPLS_MC:    return "MPLS Multicast";
    case ETH_P_ATMMPOA:    return "Multiprotocol over ATM";
    case ETH_P_PPP_DISC:   return "PPPoE Discovery";
    case ETH_P_PPP_SES:    return "PPPoE Session";
    case ETH_P_LINK_CTL:   return "HPNA/WLAN Link Local Tunnel";
    case ETH_P_8021AC:     return "IEEE 802.1AC";
    case ETH_P_ATMFATE:    return "Frame-based ATM Transport over Ethernet";

    case ETH_P_PAE:        return "IEEE 802.1X Port Access Entity";
    case ETH_P_PROFINET:   return "PROFINET";
    case ETH_P_REALTEK:    return "Realtek proprietary protocol";
    case ETH_P_AOE:        return "ATA over Ethernet";
    case ETH_P_ETHERCAT:   return "EtherCAT";
    case ETH_P_8021AD:     return "IEEE 802.1ad Service VLAN";
    case ETH_P_802_EX1:    return "IEEE 802 Local Experimental 1";
    case ETH_P_MXLGSW:     return "MaxLinear GSW DSA";
    case ETH_P_PREAUTH:    return "802.11 Preauthentication";
    case ETH_P_TIPC:       return "TIPC";
    case ETH_P_LLDP:       return "Link Layer Discovery Protocol";
    case ETH_P_MRP:        return "Media Redundancy Protocol";
    case ETH_P_MACSEC:     return "IEEE 802.1AE MACsec";
    case ETH_P_8021AH:     return "IEEE 802.1ah Backbone Service Tag";
    case ETH_P_MVRP:       return "IEEE 802.1Q MVRP";
    case ETH_P_1588:       return "IEEE 1588 Precision Time Protocol";
    case ETH_P_NCSI:       return "NCSI";
    case ETH_P_PRP:        return "Parallel Redundancy Protocol";
    case ETH_P_CFM:        return "Connectivity Fault Management";
    case ETH_P_FCOE:       return "Fibre Channel over Ethernet";
    case ETH_P_IBOE:       return "InfiniBand over Ethernet";
    case ETH_P_TDLS:       return "Tunneled Direct Link Setup";
    case ETH_P_FIP:        return "FCoE Initialization Protocol";
    case ETH_P_80221:      return "IEEE 802.21 Media Independent Handover";
    case ETH_P_HSR:        return "High-availability Seamless Redundancy";
    case ETH_P_NSH:        return "Network Service Header";

    case ETH_P_LOOPBACK:   return "Ethernet loopback packet";
    case ETH_P_QINQ1:      return "Deprecated QinQ VLAN";
    case ETH_P_QINQ2:      return "Deprecated QinQ VLAN";
    case ETH_P_QINQ3:      return "Deprecated QinQ VLAN";
    case ETH_P_YT921X:     return "Motorcomm YT921x DSA";
    case ETH_P_EDSA:       return "Ethertype DSA";
    case ETH_P_DSA_8021Q:  return "DSA fake VLAN header";
    case ETH_P_DSA_A5PSW:  return "A5PSW tag value";
    case ETH_P_IFE:        return "ForCES inter-FE LFB type";
    case ETH_P_AF_IUCV:    return "IBM AF_IUCV";
    case ETH_P_NXP_NETC:   return "NXP NETC DSA";

    case ETH_P_802_3:      return "IEEE 802.3 frame";
    case ETH_P_AX25:       return "AX.25 frame";
    case ETH_P_ALL:        return "Every packet";
    case ETH_P_802_2:      return "IEEE 802.2 frame";
    case ETH_P_SNAP:       return "SNAP frame";
    case ETH_P_DDCMP:      return "DEC DDCMP";
    case ETH_P_WAN_PPP:    return "WAN PPP frame";
    case ETH_P_PPP_MP:     return "PPP Multilink Protocol frame";
    case ETH_P_LOCALTALK:  return "LocalTalk frame";
    case ETH_P_CAN:        return "Controller Area Network frame";
    case ETH_P_CANFD:      return "CAN FD frame";
    case ETH_P_CANXL:      return "CAN XL frame";
    case ETH_P_PPPTALK:    return "AppleTalk over PPP";
    case ETH_P_TR_802_2:   return "Token Ring 802.2 frame";
    case ETH_P_MOBITEX:    return "Mobitex";
    case ETH_P_CONTROL:    return "Card-specific control frame";
    case ETH_P_IRDA:       return "Linux IrDA";
    case ETH_P_ECONET:     return "Acorn Econet";
    case ETH_P_HDLC:       return "HDLC";
    case ETH_P_ARCNET:     return "ARCnet";
    case ETH_P_DSA:        return "Distributed Switch Architecture";
    case ETH_P_TRAILER:    return "Trailer switch tagging";
    case ETH_P_PHONET:     return "Nokia Phonet";
    case ETH_P_IEEE802154: return "IEEE 802.15.4";
    case ETH_P_CAIF:       return "ST-Ericsson CAIF";
    case ETH_P_XDSA:       return "Multiplexed DSA protocol";
    case ETH_P_MAP:        return "Qualcomm MAP";
    case ETH_P_MCTP:       return "Management Component Transport Protocol";
    case ETH_P_GRE_OSI:    return "GRE tunnel / IS-IS over GRE";

    default:
        return "Unknown protocol";
    }
}

//https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_ether.h
/*
struct ethhdr {
	unsigned char	h_dest[ETH_ALEN];	// destination eth addr	
	unsigned char	h_source[ETH_ALEN];	// source ether addr	
	__be16		h_proto;		// packet type ID field	
} __attribute__((packed));
*/
void PrintPacketInfo(unsigned char* buffer,int size){
   struct ethhdr* ethhdr;
   if(size>sizeof(struct ethhdr)){
      fprintf(stdout,"PACKET\n");
      ethhdr=(struct ethhdr*)buffer;
      fprintf(stdout,"ETHERNET\n");
      fprintf(stdout,"SOURCE:" GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethhdr->h_source[0],ethhdr->h_source[1],ethhdr->h_source[2],ethhdr->h_source[3],ethhdr->h_source[4],ethhdr->h_source[5]);
      fprintf(stdout,"DEST:" GREEN("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X") "\n",ethhdr->h_dest[0],ethhdr->h_dest[1],ethhdr->h_dest[2],ethhdr->h_dest[3],ethhdr->h_dest[4],ethhdr->h_dest[5]);
      fprintf(stdout,"PROTOCOL:" GREEN("%s") "\n",GET_ETH_PROTO(ethhdr->h_proto));
      //print ip
      if(size>sizeof(struct ethhdr)+sizeof(struct iphdr)){
         unsigned int ip_proto;
	 fprintf(stdout,"IP\n");
	 ip_proto=PrintIpPacket(buffer,size);
	 switch(ip_proto){
	    case IPPROTO_ICMP:
	       PrintIcmpPacket(buffer,size);
	       break;
	    case IPPROTO_TCP:
	       PrintTcpPacket(buffer,size);
	       break;
	    case IPPROTO_UDP:
	      PrintUdpPacket(buffer,size);
	      break;
	    default:
	      fprintf(stdout,"UNSUPPORTED PROTOCOL\n");
	      HexDump("Packet Dump",(unsigned char*)(buffer+sizeof(struct ethhdr)),size);
	      break; 
	 }
      }
   }
}

void CleanUp(){
   free(buffer);
   close(sockfd);
}

int main(int argc,char* argv[]){
   InitSocket();
   InitInterface(argv[1]);
   Bind();
   ssize_t len;
   struct sockaddr_ll packet_info;
   socklen_t packet_len=sizeof(struct sockaddr_ll);
   while(1){
      memset(buffer,0,BUFFER_SIZE);
      len=recvfrom(sockfd,buffer,BUFFER_SIZE,0,(struct sockaddr*)&packet_info,&packet_len);
      if(len<0){
         fprintf(stderr,RED("RECVFORM::ERROR:") "%s\n",strerror(errno));
         exit(EXIT_FAILURE);	 
      }
      PrintPacketInfo(buffer,len);
   }
   CleanUp();
}


