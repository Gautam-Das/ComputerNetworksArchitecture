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

    // if sequence number is within the window
    if (A_next_seq_num < send_base + WINDOWSIZE) {
        if (TRACE > 1)
            printf("----A: New message arrives, send window is not full, send new message to layer3!\n");

        // create packet
        struct pkt send_pkt;
        send_pkt.seqnum = A_next_seq_num;
        send_pkt.acknum = NOTINUSE;
        for (int i = 0; i < 20; i++)
            send_pkt.payload[i] = message.data[i];
        send_pkt.checksum = compute_checksum(send_pkt);

        // store the packet in the buffer
        buffer[A_next_seq_num % WINDOWSIZE] = send_pkt;
        
        /* send out packet */
        if (TRACE > 0)
            printf("Sending packet %d to layer 3\n", send_pkt.seqnum);
        tolayer3 (A, send_pkt);

        // start timer if first packet in window
        if (A_next_seq_num == send_base) {
            starttimer(A, RTT);
        }
        A_next_seq_num = (A_next_seq_num + 1) % SEQSPACE;
    } else {
        if (TRACE > 0)
            printf("----A: New message arrives, send window is full\n");
        window_full++;
    }
}