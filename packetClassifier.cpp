#include "packetClassifier.h"

using namespace std;

ObservationPeriod::ObservationPeriod(float t) {
  syn = 0;
  syn_ackf = 0;
  syn_ackr = 0;
  diff = 0;
  initialTime = t;
}

Sample::Sample(unsigned int s, unsigned int a, bool synchr, bool acknowl, string p, float t, bool f) {
  seq = s;
  ack = a;
  syn = synchr;
  acknowledgment = acknowl;
  protocol = p;
  timePassed = t;
  fin = f;
}

Sample::Sample() {
  seq = 0;
  ack = 0;
  syn = false;
  acknowledgment = false; 
  protocol = " ";
  timePassed = 0;
  fin = false;
}

Positions::Positions(unsigned int n, bool s, bool a, bool f) {
  primes.push_back(224171);
  primes.push_back(214237);
  primes.push_back(205633);
  primes.push_back(167917);
  primes.push_back(174829);
  primes.push_back(193139);
  primes.push_back(187909);
  primes.push_back(197779);
  syn = s, ack = a;

  int sz = 8;
  for(int i=0; i<sz; i++) {
    results.push_back( (n*(n+3)) % primes[i] );
  }

  fin = f;
}

Positions::Positions(int n, unsigned int* v, bool s, bool a, bool f) {
  for(int i=0; i<n; i++) {
    results.push_back(v[i]);
  }

  syn = s;
  ack = a;
  fin = f;
}

PacketType::PacketType(Type t, bool f) {
  type = t;
  fin = f;
}

Sample PacketClassifier::getPacketInformation(ifstream &ip, bool fin){
  string helper;
  string dataLine;
  float timePassed;
  string source, destination;
  string protocol;
  unsigned int seq;
  unsigned int ack;
  bool syn;
  bool acknowledgment;

  getline(ip, dataLine);
  stringstream ss(dataLine);

  ss >> timePassed;
  ss >> source >> destination;
  ss >> seq;
  ss >> ack;
  ss >> helper;
  if(helper == "Not") {
    ss >> helper;
    syn = false;
  } else syn = true;
  ss >> helper;
  if(helper == "Not") {
    ss >> helper;
    acknowledgment = false;
  } else acknowledgment = true;
  ss >> protocol;

  return Sample(seq, ack, syn, acknowledgment, protocol, timePassed, fin);
}

Positions PacketClassifier::getHashValues(Sample sample, bool f) {
  if(sample.syn and sample.acknowledgment)
    return Positions(sample.ack - 1, sample.syn, sample.acknowledgment, f);

  else if(sample.syn)
    return Positions(sample.seq, sample.syn, sample.acknowledgment, f);

  else return Positions(0, sample.syn, sample.acknowledgment, f);
}

PacketType PacketClassifier::classifyPacket(Positions positions, unsigned int *cBloomFilter, bool f) {
  if(positions.syn and positions.ack){
    bool first = true;
    int sz = 8;
    for(int i=0; i<sz; i++) {
      first = first and cBloomFilter[positions.results[i]] > 0;
    }
    if(first) {
      int sz = 8;
      for(int i=0; i<sz; i++) cBloomFilter[positions.results[i]]--;
      return PacketType(SYN_ACKF, f);
    } else {
      return PacketType(SYN_ACKR, f);
    }
  }
  else if(positions.syn and !positions.ack){
    int sz = 8;
    for(int i=0; i<sz; i++) cBloomFilter[positions.results[i]]++;
    return PacketType(SYN, f);
  }
  else return PacketType(ACK, f);
}

void PacketClassifier::updateSample(ObservationPeriod &observationPeriod, PacketType packet) {
  switch(packet.type) {
    case SYN:
      observationPeriod.syn++;
      break;
    case SYN_ACKF:
      observationPeriod.syn_ackf++;
      break;
    case SYN_ACKR:
      observationPeriod.syn_ackr++;
      break;
    default:
      break;
  }
}

