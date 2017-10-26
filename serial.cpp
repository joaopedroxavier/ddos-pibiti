#include "packetClassifier.h"
#include <ctime>

using namespace std;

const float memoryParameter = 0.900000;
const float observationTimeInterval = 5.000000;
const float expectedValue = 1.000000;

const float verdictNumber = 500.000000;

unsigned int *cBloomFilter;

int main(int argc, const char* argv[]) {

  const clock_t startTime = clock();

  ifstream ip;
  if(argc != 2) return -1;

  cerr << "Opening file..." << endl;

  ip.open(argv[1]);
  if(!ip.is_open()) {
    cerr << "Error: Couldn't find any file." << endl;
    return -1;
  }

  cerr << memoryParameter << " " << expectedValue << " " << verdictNumber << endl;

  PacketClassifier packetClassifier;
  ObservationPeriod observationPeriod = ObservationPeriod(0);
  float time = 0, lastAverage = 0, lastX = 0;
  float y = 0, averageY = 0, averageDelta = 0, x = 0;
  float timeofAttack;
  bool hasAttack = false;
  int samplenumber = 0;

  cBloomFilter = new unsigned int[1000000];

  while(!ip.eof()){
    Sample sample = packetClassifier.getPacketInformation(ip, false);
    time = sample.timePassed;

    if(sample.protocol == "TCP" and !(sample.acknowledgment and !sample.syn)) {

      if(observationPeriod.initialTime == 0) observationPeriod.initialTime = time;

      if(time - observationPeriod.initialTime > observationTimeInterval) {
        if(observationPeriod.initialTime == 0) lastAverage = (float) observationPeriod.syn_ackf;

        else lastAverage = (float) (memoryParameter * lastAverage + (1 - memoryParameter) * observationPeriod.syn_ackf);

        lastX = ((float) observationPeriod.syn - (float) observationPeriod.syn_ackf) / lastAverage;
        x += lastX;

        y = y + lastX - expectedValue;
        averageY = averageY + y;

        averageDelta = averageDelta + lastX;

        if(y > verdictNumber) {
          if(!hasAttack){
            timeofAttack = time;
            hasAttack = true;
            int inttime = (int) timeofAttack;
            cerr << "Time of Attack: " << 8 + (inttime) / 3600 << ":" << ((inttime) % 3600) / 60 << ":" << ((inttime) % 60) << endl;
            cerr << "y: " << y << endl;
          }
        }
        if(y <= verdictNumber) hasAttack = false;
        observationPeriod = ObservationPeriod(time);
        samplenumber++;
      }

      Positions positions = packetClassifier.getHashValues(sample, false);
      PacketType packet = packetClassifier.classifyPacket(positions, cBloomFilter, false);
      packetClassifier.updateSample(observationPeriod, packet);
    }

  }

  averageDelta = averageDelta / samplenumber;
  x = x / samplenumber;
  averageY = averageY / samplenumber;
  cerr << "Done. Average delta: " << averageDelta << endl;
  printf("Average Y: %.4f\n", averageY);
  printf("Average X: %.4f\n", x);
  cerr << "Final verdict: " << (hasAttack ? "Attack" : "No attack." ) << endl;


  cerr << "Time taken: " << ( float( clock() - startTime ) ) / CLOCKS_PER_SEC << endl;

  return 0;
}
