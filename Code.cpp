
#include <stdio.h>
#include <time.h>
#include <iostream>
#include <cstdint>
#include <pcap.h>

//Calculate the IP checksum (in network byte order)
unsigned short calculateChecksum(const u_char* data, int start, int len) {
  unsigned int sum = 0;
  int i;

  // Process data in pairs of bytes
  for (i = start; i < start + len; i += 2) {
    // Combine consecutive bytes into a short (16-bit) value
    unsigned short word = ((data[i] << 8) & 0xFF00) | (data[i + 1] & 0xFF);
    sum += word;

    // Handle potential overflows (borrow from next 16-bit word)
    if ((sum & 0xFFFF0000) != 0) {
      sum &= 0xFFFF;
      sum += 1;
    }
  }

  // One's complement of the sum
  sum = ~sum;

  // Return the checksum in network byte order (big-endian)  
  return sum;
}

//Useful Reference: Winpcap Examples from the Winpcap Website (WpdPack_4_0_2 File)
//Listing Here Some Common Fields To Exploit it To Pass Covert Channels
int main()
{	    
    u_char packet[54];//All The Fileds We Used //Packet With No Data // You Can Expand It!
	pcap_if_t *alldevs;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *d;
	pcap_t *adhandle;
	int inum;
	int i=0;

	/* Retrieve the device list */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the adapter */
	if ( (adhandle= pcap_open(d->name,	// name of the device
							 65536,		// portion of the packet to capture. 
										// 65536 grants that the whole packet will be captured on all the MACs.
							 PCAP_OPENFLAG_PROMISCUOUS,			// promiscuous mode
							 1000,		// read timeout
							 NULL,		// remote authentication
							 errbuf		// error buffer
							 ) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
    
	printf("\nPacket Sending...\n");
	
	////////////////////////// Ethernet //////////////////////
	//MAC Address For Our DST: 00-0C-29-88-59-9A
	//Note: Filled Out According To Your Studied Condition
    packet[0] = 0x00;
    packet[1] = 0x0C;
    packet[2] = 0x29;
    packet[3] = 0x88;
    packet[4] = 0x59;
    packet[5] = 0x9A;
	
	//MAC Address For This Device: 00-0C-29-10-E5-B6    
	//Note: Filled Out According To Your Studied Condition
    packet[6]  = 0x00;
    packet[7]  = 0x0C;
    packet[8]  = 0x29;
    packet[9]  = 0x10;
    packet[10] = 0xE5;
    packet[11] = 0xB6;
    
	//IP Header
	//Common Status
	packet[12] = 0x08;
	packet[13] = 0x00;
	
	////////////////////////// IP //////////////////////
	packet[14]= 0x45; // Version & Header Length 

	//Common Status
	packet[15]= 0x00; // TOS			

	//Note: Filled Out According To Your Studied Condition
	packet[16]= 0x00; // Total Length: 40 byte
	packet[17]= 0x28; // Total Length: 40 byte
	
	//Note: Filled Out According To Your Studied Condition // Maybe Contain Covert Channel 
	packet[18]= 0x00; // ID
	packet[19]= 0x11; // ID	

	packet[20]= 0x40; // Flags + Fragment Offset
	packet[21]= 0x00; // Flags + Fragment Offset

	////////////////////////////////////////////////////
	packet[22]= 0x41; // TTL	//It Will Be Changed Later...
	////////////////////////////////////////////////////

	packet[23]= 0x06; // Protocol: TCP

	////////////////////////////////////////////////////
	packet[24]= 0x00; // Check Sum // Initial
	packet[25]= 0x00; // Check Sum // Initial
	////////////////////////////////////////////////////

	//Note: Filled Out According To Your Studied Condition
	packet[26]= 0xC0; // SRC IP: 192
	packet[27]= 0xA8; // SRC IP: 168
	packet[28]= 0x12; // SRC IP: 18	
	packet[29]= 0xAD; // SRC IP: 173

	//Note: Filled Out According To Your Studied Condition
	packet[30]= 0xC0; // DST IP: 192
	packet[31]= 0xA8; // DST IP: 168
	packet[32]= 0x12; // DST IP: 18
	packet[33]= 0x64; // DST IP: 100
	
	////////////////////////// TCP //////////////////////
	//Note: Filled Out According To Your Studied Condition
	packet[34]= 0x13; // SRC Port: 5000
	packet[35]= 0x88; // SRC Port: 5000

	//Note: Filled Out According To Your Studied Condition
	packet[36]= 0x00; // DST Port: 80
	packet[37]= 0x50; // DST Port: 80

	//Note: Filled Out According To Your Studied Condition // Maybe Contain Covert Channel
	packet[38]= 0x00; //Sequence //A
	packet[39]= 0x00; //Sequence //B
	packet[40]= 0x00; //Sequence //C
	packet[41]= 0x00; //Sequence //D

	//Note: Filled Out According To Your Studied Condition // Maybe Contain Covert Channel
	packet[42]= 0x00; //Ack      //A
	packet[43]= 0x00; //Ack		 //B
	packet[44]= 0x00; //Ack		 //C
	packet[45]= 0x00; //Ack		 //D

	packet[46]= 0x50; // Header Length -or- Data offset = 5 // 4 bit
	packet[47]= 0x10; // Reserved 6 bits // ARG, ACK, PSG, RST, SYN, FIN 6 bit
	//0101 000000 010000

	packet[48]= 0xFa; // Window //64240
	packet[49]= 0xF0; // Window
	//You Can Make It FFFF

	//Note: Filled Out According To Your Studied Condition // Maybe Contain Covert Channel
	packet[50]= 0xFA; // Checksum
	packet[51]= 0xA9; // Checksum
	
	//Note: Filled Out According To Your Studied Condition // Maybe Contain Covert Channel
	packet[52]= 0x00; //Urgent Pointers
	packet[53]= 0x00; //Urgent Pointers		
		
	// ------------------ Covert Channel --------------------- //      
	time_t seconds;
	seconds = time(NULL);
	//Assume we have "HELLO"
	u_char chars [5] = {0x48, 0x45, 0x4C, 0x4C, 0x4F};
	//Assume we have the follwing bits
	int code[5] = {1,0,0,1,1};            
	int j=0;   
	
    while(j<5)
	{			
		//TTL Field
		packet[22]= chars[j];	   
		packet[24]= 0x00; // Check Sum
		packet[25]= 0x00; // Check Sum
	   	seconds = time(NULL);
		printf("Seconds = %ld\n", seconds);		
		printf("Code[%d] = %d\n", j, code[j] );		
		if (code[j] == (seconds % 2))
		{
			// Calculate IP checksum (starting from IP header index 14)
			//IP Header starts at index=14 and ends at index=33, then the size is 20
			unsigned short checksum = calculateChecksum(packet, 14, 20);
			packet[24] = (checksum >> 8) & 0xFF;
			packet[25] = checksum & 0xFF;
			pcap_sendpacket(adhandle , packet , 54);//54 Is The Length Of The Packet
			printf("Send\n");			
			j++;						
		}		
		else
			printf("Wait\n");							
		Sleep(1000);		
	}      
	return 0;
}
