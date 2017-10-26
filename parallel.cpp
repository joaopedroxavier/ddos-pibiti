#include "packetClassifier.h"
#include <mpi.h>
#include <ctime>

using namespace std;

//Valores numericos necessarios para deteccao
const float memoryParameter = 0.7500000;
const float observationTimeInterval = 5.00000;
const float expectedValue = 0.500000;
const float verdictNumber = 500.000000;

//Filtro de Bloom
unsigned int *cBloomFilter;

int main(int argc, const char* argv[]) {

	const clock_t startTime = clock();

  //uso do codigo: ./parallel caminho/do/arquivo/nome_do_arquivo
	ifstream ip;
	if(argc != 2) return -1;

	MPI_Init(NULL, NULL);
	int world_size, world_rank;
	MPI_Comm_size(MPI_COMM_WORLD, &world_size);
	MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

	char processor_name[MPI_MAX_PROCESSOR_NAME];
	int name_len;
	MPI_Get_processor_name(processor_name, &name_len);

	string name = processor_name;
	cout << "Processor " << name << " running..." << endl;

	cerr << "Opening file..." << endl;

	if(world_rank == 0) {
		ip.open(argv[1]);
		if(!ip.is_open()) {
			cerr << "Error: Couldn't find any file." << endl;
			return -1;
		}
	}

	PacketClassifier packetClassifier;
	ObservationPeriod observationPeriod = ObservationPeriod(0);
	float lastAverage = 0, lastX = 0;
	float y = 0, averageY = 0, averageDelta = 0, x = 0;
	float timeofAttack = 0;
	bool hasAttack = false;
	int samplenumber = 0;

	cBloomFilter = new unsigned int[1000000];

	if(world_rank == 0) {
  // Pegar os dados no arquivo de texto. 
		string a;
		getline(ip, a);
		Sample sample;
		while(!ip.eof()){

			float timePacket;

			sample = packetClassifier.getPacketInformation(ip, true);
			timePacket = sample.timePassed;

			unsigned int numbers[2];
			int flags[3];

			numbers[0] = sample.seq, numbers[1] = sample.ack;
			flags[0] = sample.syn, flags[1] = sample.acknowledgment, flags[2] = sample.fin;


			if(sample.protocol == "TCP" and !(sample.acknowledgment and !sample.syn)) {
				MPI_Send(&numbers, 2, MPI_UNSIGNED, 1, 0, MPI_COMM_WORLD);
				MPI_Send(&flags, 3, MPI_INT, 1, 0, MPI_COMM_WORLD); 
				MPI_Send(&timePacket, 1, MPI_FLOAT, 1, 0, MPI_COMM_WORLD);
			}
		}

		unsigned int numbers[2];
		int flags[3];
		float t;

		numbers[0] = sample.seq, numbers[1] = sample.ack;
		flags[0] = sample.syn, flags[1] = sample.acknowledgment, flags[2] = false;
		t = sample.timePassed;

		MPI_Send(&numbers, 2, MPI_UNSIGNED, 1, 0, MPI_COMM_WORLD);
		MPI_Send(&flags, 3, MPI_INT, 1, 0, MPI_COMM_WORLD); 
		MPI_Send(&t, 1, MPI_FLOAT, 1, 0, MPI_COMM_WORLD);

	} else if(world_rank == 1) {
  //Calcular as funcoes de hashing.

		bool cont = true;
		while(cont) {

			unsigned int numbers[2];
			int flags[3];
			float timePacket;

			MPI_Recv(&numbers, 2, MPI_UNSIGNED, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
			MPI_Recv(&flags, 3, MPI_INT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE); 
			MPI_Recv(&timePacket, 1, MPI_FLOAT, 0, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

			Sample sample = Sample(numbers[0], numbers[1], (bool) flags[0], (bool) flags[1], " ", timePacket, (bool) flags[2]);

			Positions positions = packetClassifier.getHashValues(sample, (bool) flags[2]);

			unsigned int results[8];
			int flag;

			for(int i=0; i<8; i++) {
				results[i] = positions.results[i];
			}

			flag = flags[2];

			MPI_Send(&results, 8, MPI_UNSIGNED, 2, 0, MPI_COMM_WORLD);
			MPI_Send(&flags, 3, MPI_INT, 2, 0, MPI_COMM_WORLD);
			MPI_Send(&timePacket, 1, MPI_FLOAT, 2, 0, MPI_COMM_WORLD);

			cont = cont and (bool) flag;
		}

	} else if(world_rank == 2) {
  //Classificar o pacote como SYN, SYN_ACKF ou SYN_ACKR 

		bool cont = true;
		while(cont) {

			unsigned int results[8];
			int flags[3];
			float timePacket;

			MPI_Recv(&results, 8, MPI_UNSIGNED, 1, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
			MPI_Recv(&flags, 3, MPI_INT, 1, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
			MPI_Recv(&timePacket, 1, MPI_FLOAT, 1, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

			Positions positions = Positions(8, results, (bool) flags[0], (bool) flags[1], (bool) flags[2]);
			PacketType packet = packetClassifier.classifyPacket(positions, cBloomFilter, (bool) flags[2]);

			int typeOfPacket = packet.type;

			int flag = flags[2];

			MPI_Send(&typeOfPacket, 1, MPI_INT, 3, 0, MPI_COMM_WORLD);
			MPI_Send(&flag, 1, MPI_INT, 3, 0, MPI_COMM_WORLD);
			MPI_Send(&timePacket, 1, MPI_FLOAT, 3, 0, MPI_COMM_WORLD);

			cont = cont and (bool) flag;
		}

	} else { 
  //Atualiza as amostragens, aplicando o criterio de deteccao.

		bool cont = true;
		while(cont){

			int typeOfPacket;
			int flag;
			float timePacket;

			MPI_Recv(&typeOfPacket, 1, MPI_INT, 2, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
			MPI_Recv(&flag, 1, MPI_INT, 2, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
			MPI_Recv(&timePacket, 1, MPI_FLOAT, 2, 0, MPI_COMM_WORLD, MPI_STATUS_IGNORE);

			Type t;
			switch(typeOfPacket) {
				case 0:
					t = SYN;
					break;
				case 1:
					t = SYN_ACKF;
					break;
				case 2:
					t = SYN_ACKR;
					break;
				case 3:
					t = ACK;
					break;
				default:
					t = ACK;
			}

			PacketType packet = PacketType(t, flag);

			if(observationPeriod.initialTime == 0) observationPeriod.initialTime = timePacket;

			if(timePacket - observationPeriod.initialTime > observationTimeInterval) {
				if(samplenumber == 0) lastAverage = (float) observationPeriod.syn_ackf;

				else lastAverage = (float) (memoryParameter * lastAverage + (1 - memoryParameter) * observationPeriod.syn_ackf);

				lastX = ((float) observationPeriod.syn - (float) observationPeriod.syn_ackf) / (lastAverage);
				x += lastX;

				y = y + lastX - expectedValue;
				averageY = averageY + y;

				averageDelta = averageDelta + lastX;

				if(y > verdictNumber) {
					if(!hasAttack){
						timeofAttack = timePacket;
						hasAttack = true;
						int inttime = (int) timeofAttack;
						cerr << "Time of Attack: " << 8 + (inttime) / 3600 << ":" << ((inttime) % 3600) / 60 << ":" << ((inttime) % 60) << endl;
						cerr << "y: " << y << endl;
					}
				}

				if(y <= verdictNumber) hasAttack = false;

				observationPeriod = ObservationPeriod(timePacket);
				samplenumber++;
			}

			packetClassifier.updateSample(observationPeriod, packet);
			cont = cont and flag;
		}

		averageDelta = averageDelta / samplenumber;
		x = x / samplenumber;
		averageY = averageY / samplenumber;
		cerr << "Done. Average delta: " << averageDelta << endl;
		printf("Average Y: %.4f\n", averageY);
		printf("Average X: %.4f\n", x);
		cerr << "Final verdict: " << (hasAttack ? "Attack" : "No attack." ) << endl;

	}

	cout << float( clock() - startTime ) / CLOCKS_PER_SEC << endl;

	MPI_Finalize();

	return 0;
}
