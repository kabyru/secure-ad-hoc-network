/*
 *
 * Authentication Module
 *
 * Used for creating a authentication channel, and other authentication purposes
 *
 * Created on : 1. feb. 2011
 * Author     : Espen Graarud
 * Email      : espengra@stud.ntnu.no
 * Project    : Implementing a Secure Ad Hoc Network
 * Institution: NTNU (Norwegian University of Science & Technology), ITEM (Institute of Telematics)
 *
 * Forked by  : Kaleb Byrum
 * Modified on: 15 Jul. 2020
 * Email      : kabyru01@louisville.edu
 * Project    : CSE 693: Secure Ad Hoc Network
 * Institution: University of Louisville, KY, USA
 */

#ifndef AM_H
#define AM_H

#include "batman.h"
//#include "os.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <linux/string.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/asn1_mac.h>






//typedef struct {
//	ASN1_OBJECT *policyLanguage;
//	ASN1_OCTET_STRING *policy;
//} ProxyPolicy;
//
//typedef struct {
//	ASN1_INTEGER *pCPathLenConstraint;
//	ProxyPolicy *proxyPolicy;
//} ProxyCertInfoExtension;
//
//typedef struct PROXYPOLICY_st
//{
//	ASN1_OBJECT *policy_language;
//	ASN1_OCTET_STRING *policy;
//} PROXYPOLICY;
//
//
//typedef struct PROXYCERTINFO_st
//{
//	ASN1_INTEGER *path_length;       /* [ OPTIONAL ] */
//	PROXYPOLICY *policy;
//} PROXYCERTINFO;
//
//
//#define ASN1_F_PROXYPOLICY_NEW          450
//#define PROXYCERTINFO_OID               "1.3.6.1.5.5.7.1.14" //tester
//#define PROXYCERTINFO_OLD_OID           "1.3.6.1.4.1.3536.1.222"
//#define LIMITED_PROXY_OID               "1.3.6.1.4.1.3536.1.1.1.9"
//#define LIMITED_PROXY_SN                "LIMITED_PROXY"
//#define LIMITED_PROXY_LN                "GSI limited proxy"











/*
 * TEMP
 */
void tool_dump_memory(unsigned char *data, size_t len);



/*
 * MAYBE
 */

typedef enum key_algorithm_en{
	ECC_key = 1,
	RSA_key = 2
} key_algorithm;



/*
 *
 * TO KEEP!!!
 *
 */

/* Definitions */
#define IF_NAMESIZE			16
#define AM_PORT 			64305
#define MAXBUFLEN 			1500-20-8 //MTU - IP_HEADER - UDP_HEADER
#define SUBJECT_NAME_SIZE 	16
#define FULL_SUB_NM_SZ		3*SUBJECT_NAME_SIZE
#define AES_BLOCK_SIZE 		16
#define AES_KEY_SIZE 		16
#define AES_IV_SIZE 		16
#define RAND_LEN 			(AES_BLOCK_SIZE*48)-1	//Chosen so auth_packets are well below MAXBUFLEN

#define CRYPTO_DIR			"./.crypto/"
#define MY_KEY				CRYPTO_DIR "my_private_key"
#define MY_CERT				CRYPTO_DIR "my_pc"
#define MY_REQ 				CRYPTO_DIR "my_pc_req"
#define MY_RAND				CRYPTO_DIR "my_rand"
#define MY_SIG				CRYPTO_DIR "my_sig"
#define RECV_REQ			CRYPTO_DIR "recv_pc_req_"
#define RECV_CERT			CRYPTO_DIR "recv_pc_"
#define ISSUED_CERT			CRYPTO_DIR "issued_pc"
#define SP_CERT				CRYPTO_DIR "sp_pc"

#define RSA_KEY_SIZE		1024
//#define ECC_CURVE			NID_sect163k1
#define ECC_CURVE			NID_secp160r1
//#define ECIES_CURVE NID_secp521r1
#define ECDH_CIPHER 		EVP_aes_128_cbc()
#define ECDH_HASHER 		EVP_sha256()

/* Naming standard structs */
typedef struct addrinfo addrinfo;
typedef struct sockaddr_in sockaddr_in;
typedef struct sockaddr_storage sockaddr_storage;
typedef struct sockaddr sockaddr;
typedef struct in_addr in_addr;
typedef struct timeval timeval;


/* AM Enums */
typedef enum am_state_en {
	READY,					//0
	SEND_INVITE,			//1
	WAIT_FOR_REQ,			//2
	SEND_REQ,				//3
	WAIT_FOR_PC,			//4
	SEND_PC,				//5
	SENDING_NEW_SIGS,		//6
	SENDING_SIG,			//7
	WAIT_FOR_NEIGH_SIG,		//8
	WAIT_FOR_NEIGH_PC,		//8
	WAIT_FOR_NEIGH_SIG_ACK,	//9 - special for SP waiting for sign as "ACK" after ISSUE
	WAIT_FOR_REQ_SIG,
	LOOKING_FOR_SP,			//This is the state of the node that sends out the first REQ to neighbors to find the SP. The node holding this status will become the SP if no SP can be found.
	ON_HOLD_FOR_SP,			//State of node that is waiting for the network to find an SP. Keeps the network from adding new nodes in the meantime.
	ON_HOLD_FOR_SP_SEARCH,
	LOST_CANDIDATE

} am_state;

//This enum corresponds to the process nodes do to determine if they need to become SPs since an SP in their network is missing.
//This enum will also prevent neighboring nodes from becoming new nodes too.
//This may or may not be integrated into am_state_en. Have not decided yet.
typedef enum looking_for_sp_en { 
	HAVE_NOT_BEEN_ASKED,	//0
	HAVE_BEEN_ASKED			//1
} sp_search_state;

//This enum corresponds to the process of sending back the location of the SP node to the originator.
//Very similar to sp_search_state but this is for the reply.
typedef enum sending_back_sp_en {
	HAVE_NOT_SENT_BACK,		//0
	HAVE_SENT_BACK			//1
} sp_sendback_state;

//This enum corresponds to the process of learning which node should be the SP candidate.
typedef enum sp_candidate_en {
	NOT_ASKED,	//0
	BEEN_ASKED	//1
} sp_candidate_state;

typedef enum am_type_en{
	NO_AM_DATA,
	SIGNATURE,
	AL_FULL,
	AL_ROW,
	AUTH_INVITE,
	AUTH_REQ,
	AUTH_ISSUE,
	AUTH_ACK,
	NEIGH_PC,
	NEIGH_SIGN,
	NEIGH_PC_REQ,
	NEIGH_SIG_REQ,
	SP_LOOK_REQ,
	SP_FOUND_REPLY,
	SP_CANDIDATE_SEARCH,
	REBOOT
} am_type;

typedef enum role_type_en{
	UNAUTHENTICATED,
	AUTHENTICATED,
	RESTRICTED,
	MASTER,
	SP
} role_type;


/* AM Structs */

typedef char * secure_t;
typedef struct {

struct {
uint32_t key;
uint32_t mac;
uint32_t orig;
uint32_t body;
} length;

} secure_head_t;

typedef struct trusted_node_st {
	uint16_t 		id;			//unique
	uint32_t		addr;		//unique ip addr
	uint8_t			role;		//SP, AUTH or whatever (might use proxypolicy rules)
	unsigned char	*name;		//Unique PC subject name
	EVP_PKEY 		*pub_key;	//Public Key of node

} trusted_node;

//This is where the SP list would go
typedef struct trusted_sp_st {
	uint16_t		id;			//The unique ID of the SP node
	EVP_PKEY		*pub_key; 	//The public key of the SP node, which is used to validate nodes.
} sp_struct;

typedef struct trusted_neigh_st {
	uint16_t 		id;				//unique
	uint32_t		addr;			//unique ip addr
	uint64_t		window;			//Sliding window, if a bit is set 0 that pkt not received, else received
	uint16_t		last_seq_num;	//Used with sliding windows
	unsigned char	*mac;			//Message Authentication Code (current)
	time_t 			last_rcvd_time;
	uint8_t			num_keystream_fails;
	uint8_t 		node_role; //Added node_role here! (7/9) We may want to change this to uint8_t
} trusted_neigh;

typedef struct candidate_node_st {
	uint16_t		id;				//Unique ID
	uint32_t		time;			//Unique Timestamp
} candidate_node;

typedef struct am_packet_st {
	uint16_t 	id;
	uint8_t 	type;
	uint8_t		node_role; //Added node_role here! (7/9)
	uint16_t	found_sp_id; //Holds the ID of the SP Node found in the network.
	uint32_t	found_sp_addr; //Holds the IP address of the SP Node found in the network.
	uint16_t	num_nodes_over; //This tells how many nodes the request or reply had to travel to get to the SP node.

	//Consider expanding the entries within this packet, this will make SP Replies so much smoother.

} __attribute__((packed)) am_packet;

typedef struct routing_auth_packet_st {
	uint16_t 	rand_len;
	uint8_t 	iv_len;
	uint8_t		sign_len;
//	uint8_t 	key_len;
}__attribute__((packed)) routing_auth_packet;

//typedef struct routing_auth_packet_st {
//	unsigned char rand[RAND_LEN*(4/3)+3];
//	unsigned char key[AES_KEY_SIZE];
//	unsigned char iv[AES_IV_SIZE];
//}__attribute__((packed)) routing_auth_packet;



/* Functions */
void am_thread_init(char *dev, sockaddr_in addr, sockaddr_in broad);
void am_thread_kill();
void am_thread_kill_from_reboot();
void am_thread_init_from_reboot();
void *am_reboot();
void *am_main();

void socks_am_setup(int32_t *recv, int32_t *send);
int socks_recv_setup(int32_t *recv, addrinfo *res);
int socks_send_setup(int32_t *send);
void socks_am_destroy(int32_t *send, int32_t *recv);

void create_signature();
int openssl_cert_create_pc0(EVP_PKEY **pkey, unsigned char **subject_name);
int openssl_cert_create_req(EVP_PKEY **pkey, unsigned char **subject_name);
int openssl_cert_create_pc1(EVP_PKEY **pkey, char *addr, unsigned char **subject_name);

int openssl_cert_selfsign(X509 **x509p, EVP_PKEY **pkeyp, unsigned char **subject_name);
int openssl_cert_mkreq(X509_REQ **x509p, EVP_PKEY **pkeyp, unsigned char **subject_name);
int openssl_cert_mkcert(EVP_PKEY **pkey, X509_REQ *reqp, X509 **pc1p, X509 **pc0p, unsigned char **subject_name);

int add_ext(STACK_OF(X509_REQUEST) *sk, int nid, char *value);

int openssl_tool_seed_prng(int bytes);void *KDF1_SHA256(const void *in, size_t inlen, void *out, size_t *outlen);

void send_signature();

void auth_invite_send(sockaddr_in *sin_dest);
void auth_request_send(sockaddr_in *sin_dest);
void auth_issue_send(sockaddr_in *sin_dest);

char *all_sign_send(EVP_PKEY *pkey, EVP_CIPHER_CTX *master, int *key_count);
void neigh_sign_send(sockaddr_in *addr, char *buf);
void neigh_req_pc_send(sockaddr_in *neigh_addr);
void neigh_pc_send(sockaddr_in *sin_dest);

am_type am_header_extract(char *buf, char **ptr, int *id, role_type *role_of_rcvd_node, uint16_t *rcvd_sp_id, uint32_t *rcvd_sp_addr, uint16_t *rcvd_num_nodes_over);

int auth_request_recv(char *addr, char *ptr);
int auth_issue_recv(char *ptr);
int auth_invite_recv(char *ptr);

int neigh_sign_recv(EVP_PKEY *pkey, uint32_t addr, uint16_t id, role_type receivedRole, char *ptr, char *auth_packet);
int neigh_pc_recv(in_addr addr, char *ptr);


void openssl_key_generate(EVP_CIPHER_CTX *aes_master, int key_count, unsigned char **keyp);
void openssl_tool_gen_rand(unsigned char **rand, int len);

void openssl_key_master_select(unsigned char **key, int b);
void openssl_key_iv_select(unsigned char **iv, int b);
int aes_init(unsigned char *key_data, int key_data_len, EVP_CIPHER_CTX *e_ctx, EVP_CIPHER_CTX *d_ctx);

void openssl_key_master_ctx(EVP_CIPHER_CTX *master);
unsigned char *openssl_aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);

void al_add(uint32_t addr, uint16_t id, role_type role, unsigned char *subject_name, EVP_PKEY *key);
void neigh_list_add(uint32_t addr, uint16_t id, role_type receivedRole, unsigned char *mac_value);
int neig_list_remove(int pos);

EVP_PKEY *openssl_key_copy(EVP_PKEY *key);
int openssl_cert_read(in_addr addr, unsigned char **s, EVP_PKEY **p);

int tool_sliding_window(uint16_t seq_num, uint16_t id);

char * tool_base64_encode(unsigned char * input, int length);
unsigned char * tool_base64_decode(char * input, int in_length, int *out_length);

void *KDF1_SHA256(const void *in, size_t inlen, void *out, size_t *outlen);

int openssl_cert_add_ext_req(STACK_OF(X509_EXTENSION) *sk, int nid, char *value);

void neigh_sign_req_send(uint32_t addr);

void secure_usage();

void all_points_bulletin();
void neighbor_nudge(am_type what_purpose);
void neighbor_nudge_forward(am_type what_purpose, uint16_t senderID);
void kill_switch();
void presidential_candidacy();
int presidential_debate(long localNodeTime, long senderNodeTime);
void sp_reply_start();
void neighbor_nudge_sp_reply(am_type what_purpose, uint16_t senderID);
int neighbor_sp_scour(int senderID);
void received_candidates_add(uint32_t time, uint16_t id);
int	received_candidates_remove(int pos);
void purge_received_candidates_list();



/* Necessary external variables */
extern role_type my_role, req_role;
extern am_state my_state;
extern sp_search_state sp_search_status;
extern sp_sendback_state sp_sendback_status;
extern sp_candidate_state sp_candidate_status;
extern pthread_t am_main_thread;
extern uint32_t new_neighbor;
extern uint32_t trusted_neighbors[100];
extern unsigned char *auth_value;
extern uint16_t auth_seq_num;
extern pthread_mutex_t auth_lock;
extern int num_auth_nodes;
extern int num_trusted_neigh;
extern int num_candidate_tries;
//extern time_t localNodeTimestamp;

extern trusted_neigh *neigh_list[100];
extern candidate_node *received_candidates[100];

#endif
