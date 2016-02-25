#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>
#include "tcpstate.h"
#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

void ConstructTCPPacket();

enum PacketFlags {
    SYN = 0,
    ACK = 1,
    SYN_ACK = 3,
    FIN = 4,
    FIN_ACK = 5
};

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;
  ConnectionList<TCPState> clist = ConnectionList<TCPState>();
  while (MinetGetNextEvent(event) == 0){
    // if we received an unexpected type of event, print error
        cerr << "sanity check" << endl;

    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      cerr << "invalid event from Minet" << endl;
      //  Data from the IP layer below  //
      if (event.handle==mux) {
        Packet p;
        MinetReceive(mux,p);
        unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
        //cerr << "estimated header len="<<tcphlen<<"\n";
        p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
        IPHeader iph=p.FindHeader(Headers::IPHeader);
        TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

        //cerr << "TCP Packet: IP Header is "<< iph <<" and ";
        cerr << "TCP Header is "<< tcph << " and ";

        //cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
        Connection c;
        iph.GetDestIP(c.src);
        iph.GetSourceIP(c.dest);
        iph.GetProtocol(c.protocol);
        tcph.GetDestPort(c.srcport);
        tcph.GetSourcePort(c.destport);
                
        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
        cerr << "cs->State is: " << cs->state << endl;
        cs->Print(cerr);
        unsigned int rcvSeqNum;
        tcph.GetSeqNum(rcvSeqNum);
        cerr << "rcv seq num is: " << rcvSeqNum << endl;
        cerr << c << endl; 
        
        if(tcph.IsCorrectChecksum(p)){
            unsigned char rcvFlags;
            tcph.GetFlags(rcvFlags);
            if(IS_SYN(rcvFlags)){
                cerr << "RECEVIED A FLAG BITCH" << endl;
            }
            if(IS_ACK(rcvFlags)){
                cerr << "ack'ed a flag" << endl;
            }
        } else{
            //incorrect checksum
        }   
      }
          //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request:" << s << endl;

        switch(s.type){
            case CONNECT:
                {
                    cerr << "Socket connected" << endl;
                }
                break;
            case ACCEPT:
                {   //ignored, send ok response
                    SockRequestResponse repl;
                    repl.type = STATUS;
                    repl.connection = s.connection;
                    //buffer is zero bytes
                    repl.bytes = 0;
                    repl.error = EOK;
                    MinetSend(sock,repl);
                    cerr << "Accepted socket request" << endl;
                }
                break;
            default:
                {
                    SockRequestResponse repl;
                    // repl.type = SockRequestResponse::STATUS;
                    repl.type = STATUS;
                    repl.error = EWHAT;
                    MinetSend(sock,repl);
                    cerr << "At default case" << endl;
                }
        }
      }
    }
  }
  return 0;
}
