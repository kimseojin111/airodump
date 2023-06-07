#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include "mac.h"
#include <map>
#include <stdlib.h>
#include <iostream>
#define FIXED_PARAMETERS 12


struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));


struct BEACON_FRAME {
	u_int8_t frameControl[2];
	u_int16_t duration_id;
	u_int8_t destinationMac[6];
	u_int8_t sourceMac[6];
	u_int8_t bssid[6];
	u_int16_t seqCtrl;
} __attribute__((__packed__));


using namespace std; 

char* dev; 

void usuage(void) {
    printf("syntax : airodump <interface>\nsample : airodump mon0\n");
}

bool parse(int argc, char* argv[]){
    if(argc!=2) {
        usuage();
        return false;
    }
    dev = argv[1];
    return true;
}

struct BE {
    int Beacons; 
    char ESSID[100];
};

map<Mac,BE> mapp;

void printt(){
    system("clear");
    printf("BSSID                  Beacons  ESSID:\n");
    for(auto& pair:mapp){
        cout << static_cast<std::string>(pair.first) << "     " << pair.second.Beacons << "     " ;
        printf("%s\n",pair.second.ESSID);
    }
}


void parse_dot11(const u_char* packet, int caplen){
    ieee80211_radiotap_header* radiotap = (ieee80211_radiotap_header*)packet; 
    BEACON_FRAME* beacon = (BEACON_FRAME*)(packet + radiotap->it_len); 
    Mac bssid = Mac(beacon->bssid);
    if(beacon->frameControl[0]!=0x80) return; 
    if(mapp.count(bssid)>0){
        mapp[bssid].Beacons ++; 
    }
    //printf("beacon frame control : %x\n",beacon->frameControl[0]);
    else { 
        int idx  = (radiotap->it_len) + sizeof(BEACON_FRAME) + FIXED_PARAMETERS;
        // cout << "beacon sibal   " << sizeof(BEACON_FRAME) << "    Fixed sibal     " << FIXED_PARAMETERS << "  it_len  " << radiotap->it_len << endl; 
        // u_char* management = (packet + radiotap->it_len + sizeof(beacon) + FIXED_PARAMETERS); 
        while(idx<caplen){
            int tag_number = packet[idx]; 
            int tag_len = packet[idx+1]; 
            if(tag_number==0){
                struct BE new_BE; 
                new_BE.Beacons = 1; 
                printf("siballlllllllllllll %d\n",idx);
                for(int i=0;i<tag_len;i++) new_BE.ESSID[i] = packet[idx+2+i]; 
                new_BE.ESSID[tag_len] = '\0';
                mapp[bssid] = new_BE; 
            }
            idx += tag_len + 2; 
        }
    }
    printt();
}

int main(int argc, char* argv[]){
    if(!parse(argc, argv)) return -1; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
    while(true){
        struct pcap_pkthdr* header; 
        const u_char* packet; 
        int res = pcap_next_ex(pcap,&header,&packet); 
        if(res==0) continue; 
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        parse_dot11(packet, header->caplen);
    }
 }