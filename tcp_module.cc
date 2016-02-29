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

enum PacketFlags {
  SYN = 0,
  ACK = 1,
  SYN_ACK = 3,
  FIN = 4,
  FIN_ACK = 5
};

void ConstructTCPPacket(Packet &, ConnectionToStateMapping<TCPState> &,PacketFlags, unsigned long, unsigned long);

bool ConnectionEquals(ConnectionList<TCPState>::iterator, ConnectionList<TCPState>::iterator);

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
  //push a dummy connection for clist.end() comparisons
  Connection dummyConnection = Connection();
  TCPState dummyState = TCPState(0, CLOSED, 0);
  ConnectionToStateMapping<TCPState> dummy(dummyConnection, 0, dummyState, false);
  clist.push_back(dummy);

  double timeout; //2nd arg timeout
  while (MinetGetNextEvent(event) == 0){

    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
      cerr << "invalid minet event" << endl;
      // if we received a valid event from Minet, do processing
    } else {
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
        //cerr << "TCP Header is "<< tcph << " and ";

        //cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
        Connection c;
        iph.GetDestIP(c.src);
        iph.GetSourceIP(c.dest);
        iph.GetProtocol(c.protocol);
        tcph.GetDestPort(c.srcport);
        tcph.GetSourcePort(c.destport);
        
        //clist.Print(cerr);        
        ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
        //cerr << "cs->State is: " << cs->state << endl;
        //cs->Print(cerr);
        //cerr << "Silly debug statement\n\n";
        //cerr << cs->connection.dest;
        //cerr << clist.end()->connection.dest;
        if(ConnectionEquals(cs,clist.end())){
          cerr << "at end of iterator" << endl;
          c.dest = IPAddress(IP_ADDRESS_ANY);
          c.destport = PORT_ANY;
          cerr << " c is: " << c << endl; 
        }
        unsigned int rcvSeqNum;
        tcph.GetSeqNum(rcvSeqNum);
        unsigned int rcvAckNum;
        tcph.GetAckNum(rcvAckNum);
        //cerr << "rcv seq num is: " << rcvSeqNum << endl;
        
        if(tcph.IsCorrectChecksum(p)){
          unsigned char rcvFlags;
          tcph.GetFlags(rcvFlags);
          //if(IS_SYN(rcvFlags)){
          //    cerr << "received a flag" << endl;
          //}
          //if(IS_ACK(rcvFlags)){
          //    cerr << "ack'ed a flag" << endl;
          //}
          switch(cs->state.GetState()){
            case LISTEN:
              if(IS_SYN(rcvFlags) && !IS_ACK(rcvFlags) || IS_RST(rcvFlags)){
                cerr << "Listen state\n";
                //send syn_ack
                Packet sendp;
                unsigned long sendAckNum = rcvSeqNum + 1;//1?
                unsigned long startSendSeqNum = 0;
                unsigned short winSize = 14600;
                cs->state.SetLastSent(startSendSeqNum);
                cs->state.SetSendRwnd(winSize);
                //increment sequence number
                cs->connection.dest = c.dest;
                cs->connection.destport = c.destport;
                cs->connection.srcport = c.srcport;
                ConstructTCPPacket(sendp, *cs, SYN_ACK, startSendSeqNum, sendAckNum);
                sendp.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
                IPHeader siph= sendp.FindHeader(Headers::IPHeader);
                TCPHeader stcph = sendp.FindHeader(Headers::TCPHeader);
                //cerr << "\nPrinting sent IPHeader\n";
                //siph.Print(cerr);
                //cerr << "\nPrinting sent TCPHeader\n";
                //stcph.Print(cerr);
                MinetSend(mux, sendp);
                cs->state.SetState(SYN_RCVD);
                //window size
              }
              break;
            case SYN_RCVD:
              cerr << "Syn_rcvd state\n";
              //looking for ack num 0
              if (rcvAckNum == 1){
                //p.Print(cerr);
                cerr << "received acknum 1";
                cs->state.SetState(ESTABLISHED);
              }
              break;
            case ESTABLISHED:
              cerr << "Established state\n";
              //fin case
              cerr << "Received packet's header\n";
              tcph.Print(cerr);
              if (IS_FIN(rcvFlags)){
                cerr << "its a fin\n";
                //send ack
                Packet sendp;
                unsigned long sendAckNum = rcvSeqNum;
                unsigned long sendSeqNum = rcvAckNum + 1;
                ConstructTCPPacket(sendp, *cs, ACK, sendSeqNum, sendAckNum);
                MinetSend(mux, sendp);
                cs->state.SetState(CLOSE_WAIT);
              } else {
                //reading in data n stuff. just ack it
                cerr << p;
                Packet sendp;
                unsigned long sendAckNum = rcvSeqNum;
                unsigned long sendSeqNum = rcvAckNum + 1;
                ConstructTCPPacket(sendp, *cs, ACK, sendSeqNum, sendAckNum);
                //MinetSend(mux, sendp);
                //probably send something to scoket
              }
              break;
            case CLOSE_WAIT:
              cerr << "CLOSE_WAIT";
              break;
            default:
              cerr << "HELP";
          }
        } else {
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
          {   
            //Passive open
            //closed -> listeni
            TCPState tcpstate(0, LISTEN, 3);
            ConnectionToStateMapping<TCPState> mapping(s.connection,
                                                       3,
                                                       tcpstate,
                                                       false);
            clist.push_front(mapping);

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
          case CLOSE:
            //TODO
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
        cerr << "outside switch statement, sanity check" << endl;
      }
    }
  }
  return 0;
}

bool ConnectionEquals(ConnectionList<TCPState>::iterator c1, ConnectionList<TCPState>::iterator c2)
{
  bool equal = true;
  if(c1->connection.dest != c2->connection.dest){
    equal = false;
  } else if (c1->connection.src != c2->connection.src) {
    equal = false;
  } else if (c1->connection.srcport != c2->connection.srcport) {
    equal = false;
  } else if (c1->connection.srcport != c2->connection.srcport) {
    equal = false;
  } else if (c1->connection.protocol != c2->connection.protocol) {
    equal = false;
  }
  return equal;
}

void ConstructTCPPacket(Packet &p, ConnectionToStateMapping<TCPState> &conState,PacketFlags fs, unsigned long seqNum, unsigned long ackNum)
{
  cerr << "=================CONSTRUCTING TCP PACKET============" << endl;
  IPHeader iph;
  TCPHeader tcph;
  
  iph.SetProtocol(IP_PROTO_TCP);
  iph.SetSourceIP(conState.connection.src);
  iph.SetDestIP(conState.connection.dest); 
  iph.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
  //make this random
  unsigned short id = rand() % 65535;
  iph.SetID(id);
  iph.SetTTL(30);
  p.PushFrontHeader(iph);
  
  tcph.SetSourcePort(conState.connection.srcport, p);
  tcph.SetDestPort(conState.connection.destport, p);
  //set seq number based on the one stored in c2statemapping
  tcph.SetSeqNum(seqNum, p);    
  //also ack number
  tcph.SetAckNum(ackNum, p);
  //6 because 6 bytes see tcppacket ascii art
  tcph.SetHeaderLen(5, p);
  //blank options stuff
  //TCPOptions blank;
  //blank.len = 0;
  //memset(blank.data,0,TCP_HEADER_OPTION_MAX_LENGTH);
  //tcph.SetOptions(blank);
  //no use for thi
  tcph.SetUrgentPtr(0, p);
  unsigned char newFlags = 0;
  switch (fs) {
    case SYN:
      SET_SYN(newFlags);
      break;
    case SYN_ACK:
      SET_SYN(newFlags);
      SET_ACK(newFlags);
      break;
    case FIN:
      SET_FIN(newFlags);
      break;
    case FIN_ACK:
      SET_FIN(newFlags);
      break;
    case ACK:
      SET_ACK(newFlags);
      break;
    default:
      break;
  };
  tcph.SetFlags(newFlags, p);
  tcph.SetWinSize(14600, p);
  p.PushBackHeader(tcph);
  tcph.Print(cerr);
}

