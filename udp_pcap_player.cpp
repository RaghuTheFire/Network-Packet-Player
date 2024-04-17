#include <pcap.h>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <queue>

std::mutex mtx;
std::condition_variable cv;
std::queue < pcap_pkthdr * > pkt_queue;
bool done = false;

void send_packets(pcap_t * handle, char * device) {
  while (true) 
  {
    pcap_pkthdr * header;
    {
      std::unique_lock < std::mutex > lck(mtx);
      cv.wait(lck, [ & ] {
        return !pkt_queue.empty() || done;
      });
      if (done && pkt_queue.empty()) 
      {
        break;
      }
      header = pkt_queue.front();
      pkt_queue.pop();
    }

    if (pcap_sendpacket(handle, header -> caplen, header -> pkt_data) != 0) 
    {
      fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
    }
  }
}

int main(int argc, char * argv[]) 
{
  if (argc != 3) 
  {
    fprintf(stderr, "Usage: %s <pcap_file> <device>\n", argv[0]);
    return 1;
  }

  char * dev = argv[2];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t * handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) 
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return 1;
  }

  pcap_t * pcap = pcap_open_offline(argv[1], errbuf);
  if (pcap == nullptr) 
  {
    fprintf(stderr, "Couldn't open pcap file %s: %s\n", argv[1], errbuf);
    return 1;
  }

  std::vector < std::thread > threads;
  for (int i = 0; i < std::thread::hardware_concurrency(); i++) 
  {
    threads.emplace_back(send_packets, handle, dev);
  }

  struct pcap_pkthdr * header;
  const u_char * packet;
  while ((packet = pcap_next(pcap, & header)) != nullptr) 
  {
    std::unique_lock < std::mutex > lck(mtx);
    pkt_queue.push(header);
    cv.notify_one();
  }

  {
    std::unique_lock < std::mutex > lck(mtx);
    done = true;
  }
  cv.notify_all();

  for (auto & t: threads) 
  {
    t.join();
  }

  pcap_close(handle);
  pcap_close(pcap);

  return 0;
}
