// +build ignore
// exclude this C file from compilation by the CGO compiler

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/if.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/pid_namespace.h>
#include <linux/fdtable.h>
#include <linux/stat.h>
#include <linux/mount.h>
#include <linux/fs.h>

//HEADER_CONTENT//

struct dentries_data_t {
    struct qstr qstr_array[FILENAME_MAX/SUB_STR_MAX];
};

struct socket_entry_info_t {
    struct sock * sk;
    short type;
};

struct temp_key_t {
    enum event_type type;
    u32 pid;
};

// --------------------

BPF_HASH(trace_pids, u32, char);
BPF_HASH(forked_pids, u32, u64);
BPF_HASH(exited_pids, u32, u64);

BPF_HASH(entry_timestamps, struct temp_key_t, u64);
// BPF_HASH(file_data_handlers, struct temp_key_t, struct wr_rd_file_data_t);
// BPF_HASH(fd_handlers, struct temp_key_t, u64);
// BPF_HASH(sock_handlers, struct temp_key_t, struct socket_entry_info_t);
// BPF_HASH(iovec_handlers, struct temp_key_t, const struct iov_iter);
// BPF_HASH(kiocb_handlers, struct temp_key_t, struct kiocb);

// BPF_PERCPU_ARRAY(percpu_array_dskwrite_data, struct message_content_t, PER_CPU_ENTRIES);
// BPF_PERCPU_ARRAY(percpu_array_file_info, struct file_info_t, PER_CPU_ENTRIES);
// BPF_PERCPU_ARRAY(per_cpu_aux, struct dentries_data_t, 1);

BPF_ARRAY(whitelist_array, struct whitelist_entry_t, 30);

BPF_HASH(counts, u32, struct stats_info_t);
BPF_HASH(index_counter, u32, u64);

BPF_PERF_OUTPUT(events);

// --------------------
// Helper functions.

int static comm_equals(const char str1[TASK_COMM_LEN], const char str2[TASK_COMM_LEN]) {
	if (str1[0] != str2[0])
		return 0;
	if (str1[1] != str2[1])
		return 0;
	if (str1[2] != str2[2])
		return 0;
	if (str1[3] != str2[3])
		return 0;
	if (str1[4] != str2[4])
		return 0;
	if (str1[5] != str2[5])
		return 0;
	if (str1[6] != str2[6])
		return 0;
	if (str1[7] != str2[7])
		return 0;
	if (str1[8] != str2[8])
		return 0;
	if (str1[9] != str2[9])
		return 0;
	if (str1[10] != str2[10])
		return 0;
	if (str1[11] != str2[11])
		return 0;
	if (str1[12] != str2[12])
		return 0;
	if (str1[13] != str2[13])
		return 0;
	if (str1[14] != str2[14])
		return 0;
	if (str1[15] != str2[15])
		return 0;

	return 1;
}
struct pid_info_t static pid_info()
{
	struct pid_info_t process_info = {};
	process_info.kpid = (u32) bpf_get_current_pid_tgid();
	process_info.tgid = (u32) (bpf_get_current_pid_tgid() >> 32);
	bpf_get_current_comm(&process_info.comm, sizeof(process_info.comm));

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u32 upid = task->group_leader->thread_pid->numbers[task->nsproxy->pid_ns_for_children->level].nr;
	bpf_probe_read(&process_info.ppid, sizeof(process_info.ppid), &upid);

	return process_info;
}

int static skip_comm_struct(struct pid_info_t process_info) {
	char comm[TASK_COMM_LEN];

	if (COMM_FILTER != NULL)
	{
		strcpy(comm, COMM_FILTER);

		return comm_equals(comm, process_info.comm) == 0;
	}

	return 0;
}
int static skip_pid(u32 pid, u32 ppid)
{
    if ( PID_FILTER == 0 || trace_pids.lookup(&pid) != NULL || pid == PID_FILTER || ( CHILDS_FILTER==1 && ppid == PID_FILTER ) )
    {
        return 0;
    }

    return 1;
}
int static skip_pid_struct(struct pid_info_t process_info) {
	return skip_pid(process_info.kpid, process_info.ppid);
}
int static skip(struct pid_info_t process_info){

    char tracer_command[11] = "catbpf";
    int i, flag = 0;
    for (i = 0; i < 11; i++) {
        if (process_info.comm[i] != tracer_command[i]) {
            flag = 1;
            break;
        }
    }
    if (flag == 0) return 1;

	if (PID_FILTER != 0 && COMM_FILTER != 0) //TODO: verify!!
	{
		return skip_pid_struct(process_info) && skip_comm_struct(process_info);
	}

	if (PID_FILTER != 0)
	{
		return skip_pid_struct(process_info);
	}

	if (COMM_FILTER != 0)
	{
		return skip_comm_struct(process_info);
	}

	return 0;
}

// --------------------

u64 static incrementIndexCounter() {
    int key = 0;
    u64 *count = index_counter.lookup(&key);
    if (!count) {
        u64 new_count = 1;
        index_counter.update(&key, &new_count);
        return new_count;
    } else {
        *count += 1;
        return *count;
    }
}

void static incrementEnterCounter(enum event_type e_type) {
	struct stats_info_t *stats = counts.lookup(&e_type);
	if (!stats) {
		struct stats_info_t stats = {};
		stats.n_entries = 1;
		stats.n_exits = 0;
		stats.n_errors = 0;
		stats.n_lost = 0;
		counts.update(&e_type, &stats);
	} else {
		stats->n_entries += 1;
	}
}
void static incrementExitCounter(enum event_type e_type) {
	struct stats_info_t *stats = counts.lookup(&e_type);
	if (!stats) {
		struct stats_info_t stats = {};
		stats.n_entries = 0;
		stats.n_exits = 1;
		stats.n_errors = 0;
		stats.n_lost = 0;
		counts.update(&e_type, &stats);
	} else {
		stats->n_exits += 1;
	}
}
void static incrementErrorCounter(enum event_type e_type) {
	struct stats_info_t *stats = counts.lookup(&e_type);
	if (!stats) {
		struct stats_info_t stats = {};
		stats.n_entries = 0;
		stats.n_exits = 0;
		stats.n_errors = 1;
		stats.n_lost = 0;
		counts.update(&e_type, &stats);
	} else {
		stats->n_errors += 1;
	}
}
void static incrementLostCounter(enum event_type e_type) {
	struct stats_info_t *stats = counts.lookup(&e_type);
	if (!stats) {
		struct stats_info_t stats = {};
		stats.n_entries = 0;
		stats.n_exits = 0;
		stats.n_errors = 0;
		stats.n_lost = 1;
		counts.update(&e_type, &stats);
	} else {
		stats->n_lost += 1;
	}
}

// --------------------

void static emit_process_event(struct pt_regs *ctx, u64 timestamp, u32 pid, u32 tgid, enum event_type e_type, pid_t child_pid)
{
    struct event_context_t context = {};
	context.etype = e_type;
    context.pid = pid;
    context.tgid = tgid;
    context.ktime = timestamp;
    bpf_get_current_comm(&context.comm, sizeof(context.comm));

    struct event_process_t event = {};
    event.context = context;
    event.child_pid = child_pid;

    int sub_res = events.perf_submit(ctx, &event, sizeof(event));
    if (sub_res == 0) incrementExitCounter(e_type);
    else incrementLostCounter(e_type);
}

// --------------------
// Disk Probes
// --------------------

struct sys_enter_wr_rd_args {
	u64 __unused__;
	int __syscall_nr;
	u64 fd;
	char * buf;
	size_t count;
	long long pos;
};

struct sys_exit_wr_rd_args {
	u64 __unused__;
	int __syscall_nr;
	long ret;
};

int entry__sys_write(struct sys_enter_wr_rd_args *args) {
	struct pid_info_t proc_info = pid_info();
	if (skip(proc_info)) return 1;

	// increment enter_sys_write counter //TODO
	incrementEnterCounter(DSK_WRITE);

	return 0;
}

int exit__sys_write(struct sys_exit_wr_rd_args *args) {
	struct pid_info_t proc_info = pid_info();
	if (skip(proc_info)) return 1;

	return 0;
}

int enter_sys_pwrite64(struct sys_enter_wr_rd_args *args) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    // increment enter_sys_write counter //TODO
    incrementEnterCounter(DSK_WRITE);

    return 0;
}

int exit_sys_pwrite64(struct sys_exit_wr_rd_args *args) {
	struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}

int entry__sys_read(struct sys_enter_wr_rd_args *args)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    // increment enter_sys_read counter //TODO
    incrementEnterCounter(DSK_READ);

    return 0;
}

int exit__sys_read(struct sys_exit_wr_rd_args *args)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}

int enter_sys_pread64(struct sys_enter_wr_rd_args *args) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    // increment enter_sys_read counter //TODO
    incrementEnterCounter(DSK_READ);

    return 0;
}

int exit_sys_pread64(struct sys_exit_wr_rd_args *args) {
	struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}

long entry__do_sys_open(struct pt_regs *ctx,  int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    // increment entry__do_sys_open counter
    incrementEnterCounter(DSK_OPEN);

    return 0;
}

long exit__do_sys_open(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}


// --------------------
// Socket Probes
// --------------------

/**
 * Probe "ip4_datagram_connect" at the entry point.
 */
int entry__ip4_datagram_connect(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
        return 1;

    incrementEnterCounter(SOCKET_CONNECT);

    return 0;
}

/**
 * Probe "tcp_connect" at the entry point.
 */
int entry__tcp_connect(struct pt_regs *ctx, struct sock * sk) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    if (sk->sk_family != AF_INET && sk->sk_family != AF_INET6)
        return 1;

    return 0;
}

/**
 * Probe "connect" at the exit point.
 */
int exit__connect(struct pt_regs *ctx) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}

/**
 * Probe "inet_csk_accept" at the exit point.
 */
int exit__inet_csk_accept(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}

/**
 * Probe "sock_sendmsg" at the entry point.
 */
int entry__sock_sendmsg(struct pt_regs *ctx, struct socket * sock, struct msghdr *msg) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    if (sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6)
        return 1;

    incrementEnterCounter(SOCKET_SEND);

    return 0;
}

/**
 * Probe "sock_sendmsg" at the exit point.
 */
int exit__sock_sendmsg(struct pt_regs *ctx) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}

/**
 * Probe "sock_recvmsg" at the entry point.
 */
int entry__sock_recvmsg(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    if (sock->sk->sk_family != AF_INET && sock->sk->sk_family != AF_INET6)
        return 1;

    // increment entry__sock_recvmsg counter
    incrementEnterCounter(SOCKET_RECEIVE);

    return 0;
}

/**
 * Probe "sock_recvmsg" at the exit point.
 */
int exit__sock_recvmsg(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    return 0;
}

// --------------------
// Process Probes
// --------------------

/**
 * Handle forks.
 */
struct sched_process_fork
{
    u64 __unused__;
    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

int on_fork(struct sched_process_fork * args)
{
    struct pid_info_t proc_info = {};
    proc_info.kpid = args->parent_pid;
    bpf_probe_read(&proc_info.comm, sizeof(proc_info.comm), &args->parent_comm);
    if (skip(proc_info)) return 1;
    proc_info = pid_info();

    incrementEnterCounter(PROCESS_CREATE);

    u32 child_kpid = args->child_pid;
    u64 fork_ktime = bpf_ktime_get_ns();
    forked_pids.insert(&child_kpid, &fork_ktime);

    char zero = ' ';
    if (CHILDS_FILTER == 1) trace_pids.insert(&child_kpid, &zero);

    // emit_process_event((struct pt_regs *)args, fork_ktime, proc_info.kpid, proc_info.tgid, PROCESS_CREATE, child_kpid);

    return 0;
}


/**
 * Probe "wake_up_new_task" at the entry point.
 */
int entry__wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    struct pid_info_t proc_info = {};
    proc_info.kpid = p->pid;
    bpf_probe_read(&proc_info.comm, sizeof(proc_info.comm), &p->comm);
    if (skip(proc_info)) return 1;

    incrementEnterCounter(PROCESS_START);

    u64 *fork_ktime = forked_pids.lookup(&proc_info.kpid);
    u64 fork_actual_ktime = 0;

    if (fork_ktime == NULL) {
        fork_actual_ktime = bpf_ktime_get_ns();
    } else {
        fork_actual_ktime = *fork_ktime;
        forked_pids.delete(&proc_info.kpid);
    }

    // emit_process_event(ctx, fork_actual_ktime + 1, proc_info.kpid, p->tgid, PROCESS_START, 0);

    return 0;
}

/**
 * Handle process termination.
 */
struct sched_process_exit
{
    u64 __unused__;
    char comm[16];
    pid_t pid;
};

int on_exit(struct sched_process_exit *args)
{
    struct pid_info_t proc_info = {};
    proc_info.kpid = args->pid;
    bpf_probe_read(&proc_info.comm, sizeof(proc_info.comm), &args->comm);
    if (skip(proc_info)) return 1;
    proc_info = pid_info();

    incrementEnterCounter(PROCESS_END);

    u32 child_kpid = args->pid;
    u64 exit_ktime = bpf_ktime_get_ns();
    exited_pids.insert(&child_kpid, &exit_ktime);

    emit_process_event((struct pt_regs *)args, exit_ktime, proc_info.kpid, proc_info.tgid, PROCESS_END, child_kpid);

    return 0;
}

/**
 * Probe "do_wait" at the exit point.
 */
int exit__do_wait(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    incrementEnterCounter(PROCESS_JOIN);

    pid_t exited_pid = PT_REGS_RC(ctx);

    u64 *exit_ktime = exited_pids.lookup(&exited_pid);

    if (exit_ktime != NULL)
    {
        if (CHILDS_FILTER == 1) trace_pids.delete(&exited_pid);
        // emit_process_event(ctx, *exit_ktime + 1, proc_info.kpid, proc_info.tgid, PROCESS_JOIN, exited_pid);
        exited_pids.delete(&exited_pid);
    }

    return 0;
}

/**
 * Handle fsyncs.
 */
int exit__sys_fsync(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

	int return_value = PT_REGS_RC(ctx);
	if (return_value < 0) {
		incrementErrorCounter(FSYNC);
		return 1;
	}

	u64 fsync_time = bpf_ktime_get_ns();
    // emit_process_event(ctx, fsync_time, proc_info.kpid, proc_info.tgid, FSYNC, 0);

	return 0;
}