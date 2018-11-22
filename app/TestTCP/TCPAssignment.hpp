/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#include <E/E_TimerModule.hpp>
#include <cstdlib>

namespace E
{


#define RTT 100000000	//0.1 second in nanoseconds

#define SEQ_OFFSET 		38
#define ACK_OFFSET 		42
#define SIZE_OFFSET 	46
#define FLAGS_OFFSET 	47
#define WINDOW_OFFSET 	48
#define CHECKSUM_OFFSET 50

#define SYN_FLAG 	0b00000010
#define SYNACK_FLAG 0b00010010
#define ACK_FLAG 	0b00010000
#define FIN_FLAG	0b00000001
#define FINACK_FLAG 0b00010001

/* For all sockets */
enum class TCP_state{NONE, LISTEN, SYNSENT, SYNRCVD, ESTAB, FIN_WAIT1, FIN_WAIT2, CLOSING, TIME_WAIT, CLOSE_WAIT, LAST_ACK, CLOSED};

struct socket{
	//sockets for all processes stored in one place, need pid to search.
	int pid;
	int fd;

	//Address 
	uint16_t source_port;
	uint32_t source_ip;
	uint16_t dest_port;
	uint32_t dest_ip;

	//bound on connect(implicit) or bind(explicit)
	bool bound;
	bool listen;

	/* Things for listening socket */
	int backlog;	//for how many pending connections can be queued.
	std::list<struct socket *> * pending_list; 
	std::list<struct socket *> * estab_list;	

	//accept block
	struct sockaddr* sockaddr; //need to put values in here for fake accept
	bool accept_block;	
	//for blocking calls
	UUID uuid;

	TCP_state state;

	uint32_t fin_sequence_number;	//used for receiver side, 4-way pending read assist. buffering out of order fin.

	uint32_t sequence_number;
	uint32_t last_ack;	//so far, used for receiver sending ack

	uint32_t last_rwnd;

	uint32_t receiver_sequence_number; //so far, only used to keep track of receiver's seq as sender.

	//write buffer
	std::list< Packet *> * write_buffer;	//list of packets
	uint32_t write_buffer_size;

	//write block
	UUID write_uuid;
	bool write_block;
	uint8_t * w_buffer;	//pointer to application buffer
	int w_n;

	//read buffer
	std::list<Packet *>* read_buffer; //list of packets.
	uint32_t packet_data_read;	//how much data currently read in the frontmost packet.
	
	uint32_t to_read; //refers to what byte read() should read in terms of sequence number(used to reject redundant data packets)
	//actually points to first byte of packet, not the precise location within the packet.

	//read block
	UUID read_uuid;
	bool read_block;
	uint8_t * r_buffer;
	int r_n;

	//timer
	bool timer_running;
	UUID timer_uuid;

	int duplicate_ack;

	bool sender_fin_number;

	UUID close_uuid;
};

//20 bytes.
struct TCP_header{
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t sequence_number;
	uint32_t ack_number;
	uint8_t first_byte;
	uint8_t flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent_ptr;
}__attribute__((packed));

struct pseudoheader
{
	uint32_t source;
	uint32_t destination;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
}__attribute__((packed));


class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	uint16_t max_port = 32768; //ephemeral ports: 32768 - 61000(Linux)

	std::list<struct socket *> socket_list;	//

	int debug_count = 0;
	uint32_t debug;

	uint32_t debug2 = 0;
	uint32_t debug_size = 0;
	// /* Write buffer */
	// std::list<Packet *> write_buffer; //list of packets
	// uint32_t write_buffer_size = 0;

	// /* Read buffer */
	// char read_buffer[51200];
	// uint32_t read_buffer_size = 0;



private:
	virtual void timerCallback(void* payload) final;
	virtual void syscall_socket(UUID syscallUUID, int pid, int param1_int, int param2_int);
	virtual void syscall_close(UUID syscallUUID, int pid, int param1_int);
	virtual void syscall_bind(UUID syscallUUID, int pid, int param1_int, struct sockaddr *ptr,socklen_t param3_int);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int param1_int, struct sockaddr * sa, socklen_t * socklen);
	virtual void syscall_connect(UUID syscallUUID, int pid, int param1_int, struct sockaddr* sa, socklen_t socklen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd,struct sockaddr * addr, socklen_t * addrlen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* sa, socklen_t * len);
	virtual void syscall_write(UUID syscallUUID, int pid, int sockfd, void * buffer, int n);
	virtual void syscall_read(UUID syscallUUID, int pid, int sockfd, void * buffer, int n);

	/* Read buffer manipulation */
	// virtual bool reject(Packet * packet, struct socket * socket);
	virtual bool wrap_around(uint32_t start, uint32_t end, uint32_t sequence_number);
	virtual void add_to_sorted_read_buffer(Packet * packet, struct socket * socket);
	virtual uint32_t read_buffer_ordered_end_sequence(struct socket * socket);
	virtual uint32_t read_buffer_ordered_size(struct socket * socket);
	virtual uint32_t calculate_rwnd(struct socket * socket);
	virtual bool within_read_buffer_window(struct socket * socket, Packet * arriving_packet);

	/* Making packet */
	virtual struct TCP_header * make_header(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port, uint32_t seq_number, uint32_t ack_number,uint8_t flags, uint16_t window_size);
	virtual Packet * makeHeaderPacket(uint32_t source_ip, uint32_t dest_ip, uint16_t source_port, uint16_t dest_port, uint32_t seq_number, uint32_t ack_number,uint8_t flags,uint16_t window_size);
	virtual Packet * makeDataPacket(void * buffer, uint32_t data_size,uint32_t source_ip, uint32_t dest_ip,uint16_t source_port, uint16_t dest_port,uint32_t seq_number, uint32_t ack_number,uint8_t flags);

	/* Helper functions */
	virtual void free_resources(Packet * packet, struct TCP_header * header);
	virtual int minimum2(int a, int b);
	virtual int minimum4(int a, int b, int c,int d);

	/* Pending connection*/
	virtual void find_and_remove_from_list(std::list<struct socket *> * list, struct socket * socket);

	/* Socket */
	virtual struct socket * create_socket(int pid, int fd);
	virtual struct socket * find_socket(uint32_t source_ip, uint16_t source_port,uint32_t dest_ip, uint16_t dest_port);
	virtual struct socket * find_socket_source(uint32_t source_ip, uint16_t source_port);
	virtual struct socket * find_socket_dest(uint32_t dest_ip, uint16_t dest_port);
	virtual struct socket * find_listening_socket_source(uint32_t source_ip, uint16_t source_port);
	virtual struct socket * find_fd(int pid,int fd);
	virtual void remove_fd(int pid, int fd);
	virtual bool check_overlap_source(int pid, int fd, uint32_t ip, uint16_t port);
	virtual bool check_overlap_dest(int pid, int fd, uint32_t ip, uint16_t port);
	virtual void bind(int pid, int fd, uint32_t ip, uint16_t port);
	virtual void fake_accept(struct socket * listening_socket);
	virtual void fake_write(UUID syscallUUID, int pid, int sockfd, void * buffer, int n);
	virtual void fake_read(UUID syscallUUID, int pid, int sockfd, void * buffer, int n);
	virtual uint16_t get_port();
	virtual void free_socket(struct socket * socket);

	virtual bool within_write_buffer_window(struct socket * socket, uint32_t ack_number);

	/* Checksum */
	virtual uint16_t tcp_sum(uint32_t source, uint32_t dest, uint8_t* buffer, size_t length);
	virtual uint16_t one_sum(uint8_t* buffer, size_t size);

	/* Timer functions */
	virtual void start_timer(struct socket * socket);
	virtual void restart_timer(struct socket * socket);
	virtual void cancel_timer(struct socket * socket);

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();


	
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
