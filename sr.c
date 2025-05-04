#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "emulator.h"
#include "gbn.h"
#include "sr.h"

#define RTT  16.0       /* round trip time.  MUST BE SET TO 16.0 when submitting assignment */
#define WINDOWSIZE 6    /* the maximum number of buffered unacked packet
                          MUST BE SET TO 6 when submitting assignment */
#define SEQSPACE 12      /* the min sequence space for GBN must be at least 2*windowsize*/
#define NOTINUSE (-1)   /* used to fill header fields that are not being used */

int compute_checksum(struct pkt packet) {
    int checksum = 0;
    int i;

    checksum = packet.seqnum;
    checksum += packet.acknum;
    for (i = 0; i < 20; i++)
        checksum += (int)(packet.payload[i]);

    return checksum;
}
bool is_corrupted(struct pkt packet) {
    if (packet.checksum == compute_checksum(packet))
        return false;
    else
        return true;
}

/********* Sender (A) variables and functions ************/
static struct pkt buffer[SEQSPACE];  /* array for storing packets waiting for ACK */
static bool acked[SEQSPACE]; /* array for storing ACKs received */
static int send_base; /* the first packet in the window */
static int A_next_seq_num; /* the next sequence number to be used by the sender */


void A_init(void) {
    /* initialise A's window, buffer and sequence number */
    A_next_seq_num = 0;
    send_base = 0;   

}

void A_output(struct msg message) {
    // when data is received from layer 5,
    // check the next available sequence number
    // if the sequence number is within the window
    // packetize the data and send it to layer 3
    // else drop the packet

    // for the time, only track the oldest un'acked packet
    // which should be the first packet in the window

}