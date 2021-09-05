#define PID_FILTER 		//PID_FILTER//
#define COMM_FILTER 	NULL
#define CHILDS_FILTER	1

#define TASK_COMM_LEN	16
#define FILENAME_MAX	1024
#define SUB_STR_MAX		64
#define MAX_BUF_SIZE 	4096
#define PER_CPU_ENTRIES 32768 //131072
#define WHITE_FILE_LEN 	60
#define WHITELIST_SIZE 	//WHITELIST_SIZE//

enum event_type {
	SOCKET_SEND = 8,
	SOCKET_RECEIVE = 9,
	SOCKET_CONNECT = 11,
	SOCKET_ACCEPT = 12,

	PROCESS_CREATE = 1,
	PROCESS_START = 2,
	PROCESS_END = 3,
	PROCESS_JOIN = 4,

	FSYNC = 13,

	DSK_WRITE = 21,
	DSK_READ = 22,
	DSK_OPEN = 23,
	DSK_CLOSE = 24,
};

const char * const event_str[] =
{
    [SOCKET_SEND] 	 = "sock_send",
    [SOCKET_RECEIVE] = "sock_receive",
    [SOCKET_CONNECT] = "sock_connect",
	[SOCKET_ACCEPT]  = "sock_accept",

	[PROCESS_CREATE] = "process_create",
	[PROCESS_START]  = "process_start",
	[PROCESS_END]  	 = "process_end",
	[PROCESS_JOIN]   = "process_join",

	[FSYNC]   		 = "fsync",

	[DSK_WRITE]   	 = "disk_write",
	[DSK_READ]   	 = "disk_read",
	[DSK_OPEN]   	 = "disk_open",
	[DSK_CLOSE]   	 = "disk_close",
};

typedef struct socket_event_t {

} socket_event_t;

/* Common part of all events. */
typedef struct event_context_t {

	char comm[TASK_COMM_LEN];			// 16 bytes
	uint64_t ktime;						// 8 bytes
	enum event_type etype;				// 4 bytes
	uint32_t pid;						// 4 bytes
	uint32_t tgid;						// 4 bytes
} __attribute__((packed)) event_context_t;

typedef struct event_disk_t {

	struct event_context_t context;		// 36 bytes
	int index;							// 4 bytes
	int n_ref;							// 4 bytes
	uint16_t cpu;						// 2 bytes
} __attribute__((packed)) event_disk_t;


typedef struct event_disk_data_t {
	struct event_disk_t disk_info;		// 46 bytes
	int size;							// 4 bytes
	int returned_value;					// 4 bytes
} __attribute__((packed)) event_disk_data_t ;

typedef struct socket_info_t {
    uint64_t saddr[2];
    uint64_t daddr[2];
	uint16_t sport;
    uint16_t dport;
    uint16_t family;
	uint16_t type;
} __attribute__((packed)) socket_info_t;

typedef struct event_socket_t {

	struct event_context_t context;
	struct socket_info_t socket;
} __attribute__((packed)) event_socket_t;


typedef struct event_socket_data_t {

	struct event_socket_t socket_info;
	int size;							// 4 bytes
	int returned_value;					// 4 bytes
	int index;							// 4 bytes
	int n_ref;							// 4 bytes
	uint16_t cpu;						// 2 bytes

} __attribute__((packed)) event_socket_data_t;

typedef struct event_process_t {

	struct event_context_t context;
	uint32_t child_pid;
} __attribute__((packed)) event_process_t;

typedef struct message_content_t {
	char msg[MAX_BUF_SIZE];				// 4096 bytes
	uint64_t msg_len;					// 8 bytes
    int n_ref;   						// 4 bytes
}  message_content_t;


struct pid_info_t {
	uint32_t ppid;
	uint32_t kpid;
	uint32_t tgid;
	char comm[TASK_COMM_LEN];
};

typedef struct stats_info_t {
	uint32_t n_entries;
	uint32_t n_exits;
	uint32_t n_errors;
	uint32_t n_lost;
} __attribute__((packed)) stats_info_t;

struct wr_rd_file_data_t {
    char *buf;
    size_t count;
    long long offset;
};

struct file_info_t {
    uint64_t filename_len;				// 8 bytes
	uint64_t fd;						// 8 bytes
    int64_t offset;						// 8 bytes
    int32_t pipe_no;					// 4 bytes
	int n_ref;							// 4 bytes
	char filename[FILENAME_MAX];		// 1024 bytes
} file_info_t;


typedef struct whitelist_entry_t {
    int size;
	char name[WHITE_FILE_LEN];
} whitelist_entry_t;

int static is_disk_event(enum event_type type) {
    return type == DSK_WRITE || \
        type == DSK_READ || \
        type == DSK_OPEN || \
        type == DSK_CLOSE;
}
int static is_socket_event(enum event_type type) {
    return type == SOCKET_CONNECT || \
        type == SOCKET_ACCEPT || \
        type == SOCKET_SEND || \
        type == SOCKET_RECEIVE;
}
int static is_process_event(enum event_type type) {
    return type == PROCESS_CREATE || \
        type == PROCESS_START || \
        type == PROCESS_JOIN || \
        type == PROCESS_END;
}
