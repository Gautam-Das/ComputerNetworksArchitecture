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

void A_timerinterrupt(void) {
    // since the timer is only tracking the first packet in the window
    // resend the first packet in the window
    // and restart the timer

    if (TRACE > 0)
        printf("----A: time out, resending packet!\n");
    
    struct pkt base_packet = buffer[send_base];
    tolayer3(A, base_packet);
    packets_resent++;
    starttimer(A, RTT);
}

void A_input(struct pkt packet) {
    // when an ACK is received from layer 3
    // check if the ACK is corrupted
    if (is_corrupted(packet)) {
        if (TRACE > 0)
            printf("----A: corrupted ACK %d is received\n", packet.acknum);
        return;
    }
    total_ACKs_received++;
    
    // check if the ACK is within the window
    if (packet.acknum < send_base || packet.acknum >= A_next_seq_num) {
        if (TRACE > 0)
            printf("----A: ACK %d is out of window\n", packet.acknum);
        return;
    }

    // check if the ACK is a new ACK or a duplicate
    if (acked[packet.acknum]) {
        if (TRACE > 0)
            printf("----A: duplicate ACK %d received, do nothing!\n", packet.acknum);
        return;
    }

    acked[packet.acknum] = true; // mark the ACK as received
    new_ACKs++;

    // if the ACK is the first packet in the window
    // stop the timer and slide the window to the right
    if (packet.acknum == send_base) {
        if (TRACE > 0)
            printf("----A: ACK %d is for base packet\n", packet.acknum);
        stoptimer(A); // stop the timer
    }

    // slide the window to the right until the first unacked packet is found
    while (send_base != A_next_seq_num && acked[send_base]) {
        acked[send_base] = false; // mark the ACK as not received
        send_base = (send_base + 1) % SEQSPACE;
    }

    // if current base_packet is unacked, start new timer
    if (send_base != A_next_seq_num) {
        starttimer(A, RTT); // start the timer for the new base packet
    } else {
        stoptimer(A); // stop the timer if all packets are ACKed
    }
}

