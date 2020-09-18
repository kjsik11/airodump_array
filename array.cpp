#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <list>

void airodump(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int cnt;

struct beacons{
    int PWD;
    int beacons;
    int bssid[6];
    char essid[30];
    u_int8_t ssid_len;
}beacon[200];


int main(int argc, char *argv[])
{


    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    printf("%s\n",dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    }
    u_char *arg =NULL;
    pcap_loop(handle,0,pcap_handler(airodump),arg);


    pcap_close(handle);
        return(2);
}


void print_beacon(struct beacons *beacon){
    int count =0;
    printf("BSSID                   Beacons  PWD(notdBm) ESSID\n");
    printf("======================================================\n");
    for(int i=0;i<cnt;i++){
        for(int k=0;k<6;k++){
            printf("%2x",beacon[count].bssid[k]);
            if(k<5)
                printf(":");
        }



        printf("%10d",beacon[count].beacons);
        printf("%10d",beacon[count].PWD);
        printf("\t");
        for(int k=0;k<beacon[count].ssid_len;k++){
            printf("%c",beacon[count].essid[k]);
        }
        printf("\n");
        count++;
    }
}

void airodump(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    if(*(pkt_data+24)==128){


    int a=0;
    int s1=0;
    int count = 0;
    int temp_bssid[6];
    for(int k=0;k<6;k++){
        temp_bssid[k]=*(pkt_data+40+k);
    }
    for(int k=0;k<cnt;k++){
        s1=0;
        for(int i=0;i<6;i++){
            if(beacon[count].bssid[i]==temp_bssid[i])
                    s1++;
        }
        if(s1==6){
            a=1;
            break;
        }
        count++;
    }
    if(a==1){
        beacon[count].beacons++;
    }
    else{
        beacon[cnt].PWD = *(pkt_data+18);
        beacon[cnt].beacons=0;
        for(int k=0;k<6;k++){
            beacon[cnt].bssid[k] = temp_bssid[k];
        }


        beacon[cnt].ssid_len = *(pkt_data+61);
        for(int k=0;k<beacon[cnt].ssid_len;k++){
            beacon[cnt].essid[k]=*(pkt_data+62+k);

        }
        cnt++;

    }
    }
        system ("clear");
        print_beacon(beacon);
        printf("\n");


}


