#ifndef PACKET_CLASSIFIER_H
#define PACKET_CLASSIFIER_H

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>


struct ObservationPeriod {
  unsigned int syn;
  unsigned int syn_ackf;
  unsigned int syn_ackr;
  float diff;
  float initialTime;

  public:
    ObservationPeriod(float t);
};

struct Sample {
  unsigned int seq;
  unsigned int ack;
  bool syn;
  bool acknowledgment;
  std::string protocol;
  float timePassed;
  bool fin;

  public:
    Sample(unsigned int s, unsigned int a, bool syn, bool ack, std::string p, float t, bool f);
    Sample();
};

struct Positions {
  std::vector<unsigned int> primes;
  std::vector<unsigned int> results;
  bool syn, ack;
  bool fin;
  
  public:
    Positions(unsigned int n, bool s, bool a, bool f);
    Positions(int n, unsigned int* v, bool s, bool a, bool f);
};

enum Type {SYN, SYN_ACKF, SYN_ACKR, ACK};

struct PacketType {
  Type type;
  bool fin;

  public:
    PacketType(Type t, bool f);
    PacketType();
};

class PacketClassifier {

  public:
    Sample getPacketInformation(std::ifstream &ip, bool f);
    Positions getHashValues(Sample sample, bool f);
    PacketType classifyPacket(Positions positions, unsigned int *cBloomFilter, bool f);
    void updateSample(ObservationPeriod &observationPeriod, PacketType packet);
};

#endif
