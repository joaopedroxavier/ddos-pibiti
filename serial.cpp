#include <iostream>
#include <fstream>
#include <sstream>

using namespace std;

unsigned int *cBloomFilter;
const float memoryParameter = 0.900000;
const float expectedValue = 10.000000;
const float VERDICT_NUMBER = 500.000000;

unsigned int hash1(unsigned int n){ return (n*(n+3)) % 224171; }
unsigned int hash2(unsigned int n){ return (n*(n+3)) % 214237; }
unsigned int hash3(unsigned int n){ return (n*(n+3)) % 205633; }
unsigned int hash4(unsigned int n){ return (n*(n+3)) % 167917; }
unsigned int hash5(unsigned int n){ return (n*(n+3)) % 174829; }
unsigned int hash6(unsigned int n){ return (n*(n+3)) % 193139; }
unsigned int hash7(unsigned int n){ return (n*(n+3)) % 187909; }
unsigned int hash8(unsigned int n){ return (n*(n+3)) % 197779; }

struct ObservationPeriod{
  unsigned int syn;
  unsigned int syn_ackf;
  unsigned int syn_ackr;
  float diff;
  float initialTime;
  ObservationPeriod(float t): syn(0), syn_ackf(0), syn_ackr(0), diff(0), initialTime(t){}
};

void classifyPacket(unsigned int seq, unsigned int ack, bool syn, bool acknowledgment, ObservationPeriod& sample){
  if(syn and acknowledgment){
    unsigned int h1 = hash1(ack-1), h2 = hash2(ack-1);
    unsigned int h3 = hash3(ack-1), h4 = hash4(ack-1);
    unsigned int h5 = hash5(ack-1), h6 = hash6(ack-1);
    unsigned int h7 = hash7(ack-1), h8 = hash8(ack-1);
    
    if(cBloomFilter[h1] > 0 or cBloomFilter[h2] > 0 or
        cBloomFilter[h3] > 0 or cBloomFilter[h4] > 0 or
        cBloomFilter[h5] > 0 or cBloomFilter[h6] > 0 or
        cBloomFilter[h7] > 0 or cBloomFilter[h8] > 0){
      //it means the packet is a first syn_ack packet
      cBloomFilter[h1]--, cBloomFilter[h2]--;
      cBloomFilter[h3]--, cBloomFilter[h4]--;
      sample.syn_ackf++;
      
//      cerr << "This is a syn_ackf packet! We now have " << sample.syn_ackf << " packets." << endl;
    }
    else{
      //then it's just a retransmission packet
      sample.syn_ackr++;
//      cerr << "This is a syn_ackr packet! We now have " << sample.syn_ackr << " packets." << endl;
    }
  }
  else if(syn){
    unsigned int h1 = hash7(seq), h2 = hash8(seq);
    unsigned int h3 = hash7(seq), h4 = hash8(seq);
    unsigned int h5 = hash7(seq), h6 = hash8(seq);
    unsigned int h7 = hash7(seq), h8 = hash8(seq);
    cBloomFilter[h1]++, cBloomFilter[h2]++;
    cBloomFilter[h3]++, cBloomFilter[h4]++;
    cBloomFilter[h5]++, cBloomFilter[h6]++;
    cBloomFilter[h7]++, cBloomFilter[h8]++;
    sample.syn++;
//      cerr << "This is a syn packet! We now have " << sample.syn << " packets." << endl;
  }
  sample.diff = (float)(sample.syn_ackf - sample.syn);
}

void printPacketInfo(float timepassed, string source, unsigned int ack, unsigned int seq, string destination, string protocol, bool syn, bool acknowledgment, int& number){
  cerr << endl;
  cerr << "Packet #" << number << " [" << protocol << "]:" << endl;
  cerr << endl;
  cerr << "Time: " << timepassed << endl;
  cerr << "Source: " << source << endl;
  cerr << "Destination: " << destination << endl;
  cerr << "Sequence Number: " << seq << endl;
  cerr << "Acknowledgment Number: " << ack << endl;
  cerr << "Syn: " << syn << endl;
  cerr << "Acknowledgment: " << acknowledgment << endl;
}

int main(int argc, const char* argv[]){

  ifstream ip;

  if(argc != 2) return -1;

  cerr << "Opening file..." << endl;

  ip.open(argv[1]);
  if(!ip.is_open()){
    cerr << "Error: Couldn't find any file." << endl;
    return -1;
  }

  string helper;
  string dataLine;
  float timepassed;
  string source;
  string destination;
  string protocol;
  unsigned int seq;
  unsigned int ack;
  bool syn;
  bool acknowledgment;
  int packetnumber = 0, samplenumber = 0;

  float lastAverage;
  float lastX;
  float averageDelta = 0;
  float y = 0;
  float averageY = 0;

  getline(ip, dataLine);

  ObservationPeriod sample = ObservationPeriod(0);
  cBloomFilter = new unsigned int[1000000];

  cerr << "Handling data..." << endl;

  bool hasAttack = false;
  float timeofAttack;

  while(!ip.eof()){
    getline(ip, dataLine);
    stringstream ss(dataLine);
    ss >> timepassed;
    ss >> source;
    ss >> destination;
    ss >> seq;
    ss >> ack;
    ss >> helper;
    if(helper == "Not"){
      ss >> helper;
      syn = false;
    } else syn = true;
    ss >> helper;
    if(helper == "Not"){
      ss >> helper;
      acknowledgment = false;
    } else acknowledgment = true;
    ss >> protocol;

    packetnumber++;

    if(protocol == "TCP" and !(acknowledgment and !syn)){
//      printPacketInfo(timepassed, source, ack, seq, destination, protocol, syn, acknowledgment, packetnumber);

      if(timepassed - sample.initialTime > (float)1){
        if(sample.initialTime == 0) lastAverage = (float)sample.syn_ackf;
        else lastAverage = (float)(memoryParameter * lastAverage + (1 - memoryParameter) * sample.syn_ackf);

        if(sample.syn > sample.syn_ackf) lastX = (sample.syn - sample.syn_ackf) / lastAverage;
        else lastX = 0;

        y = y + lastX - expectedValue;
        averageY = averageY + y;

        averageDelta = averageDelta + lastX;
        samplenumber++;
/* 
        cerr << "Sample #" << samplenumber++ << ": From time " << sample.initialTime << " to " << timepassed << endl;
        cerr << endl;
        cerr << "Value of y(n): " << y << endl;
        cerr << "Verdict: " << ((y > VERDICT_NUMBER) ? "Attack!" : "No attack.") << endl;
        cerr << endl;
*/
        if(y > VERDICT_NUMBER){
          if(!hasAttack){
            timeofAttack = timepassed;
            hasAttack = true;
            int inttime = (int)timeofAttack;
            cerr << "Time of Attack: " << 8 + (inttime)/3600 << ":" << ((inttime)%3600)/60 << ":" << ((inttime)%60) << endl;
            cerr << "y: " << y << endl;
          }
        }
        if(y <= VERDICT_NUMBER){
          hasAttack = false;
        }
          
        sample = ObservationPeriod(timepassed);
      }
      classifyPacket(seq, ack, syn, acknowledgment, sample);
    }

  }

  averageDelta = averageDelta / samplenumber;
  averageY = averageY / samplenumber;
  cerr << "Done. Average delta: " << averageDelta << endl;
  printf("Average Y: %.4f\n", averageY);
  cerr << "Final verdict: " << (hasAttack ? "Attack" : "No attack.") << endl;

  return 0;
}
