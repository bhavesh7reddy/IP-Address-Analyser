#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <ctype.h>
#include <string.h>

#ifdef __APPLE__
    #include <netinet/if_ether.h>       // if running on mac
#else
    #include <netinet/ether.h>          // if running on linux
#endif

#include "capture.h"
#include "ipv4.h"


int main(int argc, char **argv)
{
    printf("\n[ CN NETWORK PROJECT : IP ADDRESS VALIDITY & ANALYSIS ]\n\n");
    printf("1. Use Device Network to find various IP addresses\n");
    printf("2. Enter the IP address manually \n");
    int op;
    scanf("%d",&op);
    if(op==1)
    {
        if (argc < 2) {
        fprintf(stderr, "Must have an argument, either a file name or '-'\n");
        return -1;
        }
        printf("SNIFFING THE NETWORK\n");
        char errbuff[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_offline(argv[1], errbuff);
        if (NULL == handle)
        {
            printf("Error: %s\n", errbuff);
            return 1;
        }

        pcap_loop(handle, 1024*1024, got_packet, NULL);
        pcap_close(handle);
        printf("\nVarious Source and Destination IP address are captured from the network in different interfaces\n");
        int ctr=1;
        for(int j=0;j<i;j++)
        {
            printf("%2d. Source Address : %15s     ||    Destination Address : %15s\n",ctr,addresses_data[j].src_ip,addresses_data[j].dest_ip);
            ctr++;
        }
        printf("SELECT AN OPTION TO GET MORE INFORMATION ABOUT THAT IP ADDRESS\n");
        int n;
        int ch;
        scanf("%d",&n);
        n--;
        printf("Enter whether to work on source (Enter 1) or destination ip (Enter 2) \n");
        scanf("%d",&ch);
        char ip[100];

        if(ch==1)
        {
            strcpy(ip,addresses_data[n].src_ip);
        }
        else if(ch==2)
        {
            strcpy(ip,addresses_data[n].dest_ip);
        }
        else
        {
            printf("INVALID OPTION EXITING ....\n");
            exit(0);
        }
        char mask[4];
        mask[0]=ip[0];
        mask[1]=ip[1];
        mask[2]=ip[2];
        char class;
        int mk;
        if(strchr(mask,'.')!=NULL)
        {
            class='A';
        }
        else
        {
            mk=atoi(mask);
        }
        if(mk>=100 && mk<=127)
        {
            class='A';
        }
        else if(mk>=128 && mk<=191)
        {
            class='B';
        }
        else  if(mk>=192 && mk<=223)
        {
            class='C';
        }
        else  if(mk>=224 && mk<=239)
        {
            class='D';
        }
        else
        {
            class='E';
        }

        printf("The Selected IP address is %s and belongs to class %c \n",ip,class);
        if(class=='D' || class =='E')
        {
            printf("The the network and host bits are not defines for these classes and hence further analysis of the IP address not possible\n");
            printf("Exiting......\n");
            exit(0);
        }
        if(class=='A')
        {
            strcat(ip,"/8");
        }
        else if(class=='B')
        {
            strcat(ip,"/16");
        }
        else
        {
            strcat(ip,"/24");
        }
        ip_analysis_func(ip);
    }
    else if(op==2)
    {
        printf("Enter the IP address (address/mask)\n");
        char ip_address[100];
        scanf("%s",ip_address);
        ip_analysis_func(ip_address);
    }
    else
    {
        printf("INVALID OPTION\nEXITING........\n");
        exit(0);
    }
    exit(1);
}