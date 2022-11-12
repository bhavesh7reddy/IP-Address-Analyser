#include <stdio.h>
#include <stdlib.h>
#include <math.h>


#define BUFFER 100

unsigned int ip_number = 0;
unsigned int mask_number = 0, number_of_mask_bits;

void usage(char * ip_name, char * error_message)
{
    printf("\n%s\n%s <ip-addr/mask or net-addr/mask>\n\n", error_message, ip_name);
    exit(EXIT_FAILURE);
}

int get_input_size(char *input)
{
    int size = 0;

    for(int i = 0; input[i] != 0; i++)
    {
        size++;
    }

    return size;
}

int get_number_of_slashes(char *input)
{
    int numberOfSlashes = 0;

    for(int i = 0; input[i] != 0; i++)
    {
        if (input[i] == '/') {
            numberOfSlashes++;
        }
    }

    return numberOfSlashes;
}

int get_slash_position(char *input)
{
    int slashPosition = 0;

    for(int i = 0; input[i] != 0; i++)
    {
        if (input[i] == '/') {
            return i;
        }
    }

    return 0;
}

int is_valid_ip_address(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}

int is_valid_mask(char * mask_string)
{
    char *end;
    int i = strtol(mask_string, &end, 10);

    return i < 31;
}

void get_ip_string(char * input, char * destination, int slashPosition) {
    for (int i = 0; i < slashPosition; i++) {
        destination[i] = input[i];
        destination[i + 1] = 0;
    }
}

void get_mask_string(char * input, char * destination, int slashPosition) {
    for (int i = slashPosition + 1, j = 0; input[i] != 0; i++, j++) {
        destination[j] = input[i];
        destination[j + 1] = 0;
    }
}

void print_ip_address(int * number_addr)
{
    unsigned char * raw_ptr; // pointer to get single bytes
    int i, aux_int;
    raw_ptr = (unsigned char *) number_addr;

    for (i = 3; i > -1; i--) // run through the four integer bytes
    {
        aux_int = raw_ptr[i];
        printf("%d", aux_int);
        if(i != 0)
            printf(".");
    }
    printf(" ");
}

void binary_print(unsigned int number)
{
    unsigned int mask = 0xff000000; // last byte mask
    unsigned int shift = 24; // separate bytes
    unsigned int byte, byte_iterator, bit_iterator; // auxiliary variables

    for(byte_iterator = 0; byte_iterator < 4; byte_iterator++) // byte iterator
    {
        byte = (number & mask) >> shift;
        printf(" ");

        for(bit_iterator = 0; bit_iterator < 8; bit_iterator++) // bit iterator
        {
            if(byte & 128) // print bit values
                printf("1");
            else
                printf("0");
            byte <<= 1;
        }
        mask >>= 8; // adjust mask for next byte
        shift -= 8; // adjust shift for next byte

    }
}

// store the results in the global variables
void handle_input(char * string)
{
    unsigned int i, shift, temp = 0;

    // makes the input string an integer number in ip_number
    shift = 24;
    ip_number = (atoi(&string[0]) << shift);
    shift -= 8;

    for(i = 0; string[i] != 0; i++)
    {
        if(string[i] == 46) // check if it's a dot and get the value after it

        {
            ip_number += (atoi(&string[i + 1]) << shift);
            shift -= 8;
        }
    }

    // gets the number of bits of the mask
    for(i = 0; string[i] != 0; i++)
    {
        if(string[i] == 47) // check if it's a slash and get the value after it
        {
            number_of_mask_bits += atoi(&string[i + 1]);
        }
    }

    // makes the mask an integer number
    for(i = 31; i > (31 - number_of_mask_bits); i--)
    {
        temp = (1 << i);
        mask_number += temp;
    }
}

void ip_analysis_func(char * ip)
{
    unsigned int network_address = 0;
    unsigned int broadcast = 0;
    unsigned int host_min = 0;
    unsigned int host_max = 0;
    double number_of_hosts_bits = 0;
    char ip_string[15];
    char mask_string[4];


    int inputSize = get_input_size(ip);

    if (inputSize > 18)
    {
        usage(ip, "Must provide a valid ip/mask");
    }

    int numberOfSlashes = get_number_of_slashes(ip);

    if (numberOfSlashes != 1)
    {
        usage(ip, "Must provide a valid ip/mask");
    }

    int slashPosition = get_slash_position(ip);

    if (slashPosition == 0 || slashPosition == inputSize - 1)
    {
        usage(ip, "Must provide a valid ip/mask");
    }

    get_ip_string(ip, ip_string, slashPosition);

    if (!is_valid_ip_address(ip_string))
    {
        usage(ip, "INVALID IP ADDRESS\n");
    }

    get_mask_string(ip, mask_string, slashPosition);

    if (!is_valid_mask(mask_string))
    {
        usage(ip, "Must provide a valid ip/mask");
    }

    printf("\n");
    printf("The given IP Address is valid : %s\n", ip);
    printf("\n");

    // transform the given input in numbers
    handle_input(ip);

    // calculating values through the global variables
    network_address = ip_number & mask_number;
    broadcast = ~(mask_number);
    broadcast = broadcast + network_address;
    host_min = network_address + 1;
    host_max = broadcast - 1;

    // printing the results
    printf("Network Address: ");
    printf("\t");
    binary_print(network_address);
    printf("\t");
    print_ip_address(&network_address);
    printf("\n");

    printf("Subnetmask:          ");
    printf("\t");
    binary_print(mask_number);
    printf("\t");
    print_ip_address(&mask_number);
    printf("(%d bits)", number_of_mask_bits);
    printf("\n");

    printf("Broadcast Address:   ");
    printf("\t");
    binary_print(broadcast);
    printf("\t");
    print_ip_address(&broadcast);
    printf("\n");

    printf("First Host Address:   ");
    printf("\t");
    binary_print(host_min);
    printf("\t");
    print_ip_address(&host_min);
    printf("\n");

    printf("Last Host Address:   ");
    printf("\t");
    binary_print(host_max);
    printf("\t");
    print_ip_address(&host_max);
    printf("\n");
    printf("\n");

    number_of_hosts_bits = 32 - number_of_mask_bits;
    int no_of_addresses=(int)pow(2, number_of_hosts_bits);
    printf("The total number of addresses avaliable in the network are %d\n",no_of_addresses);
    printf("The possible number of hosts on this network is %d.\n", (int)pow(2, number_of_hosts_bits) - 2);
    printf("Enter the number of addresses (size) to be allocated using this network to each block\n");
    int no;
    scanf("%d",&no);
    int power = 1;
    while(power < no)
    {
        power*=2;
    }
    int blocks=no_of_addresses/power;
    printf("The number of blocks that be accommodated with %d addresses in this network are %d ",power,blocks);
    printf("\n");
}
