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
BPF_HASH(file_data_handlers, struct temp_key_t, struct wr_rd_file_data_t);
BPF_HASH(fd_handlers, struct temp_key_t, u64);
BPF_HASH(sock_handlers, struct temp_key_t, struct socket_entry_info_t);
BPF_HASH(iovec_handlers, struct temp_key_t, const struct iov_iter);
BPF_HASH(kiocb_handlers, struct temp_key_t, struct kiocb);

BPF_PERCPU_ARRAY(percpu_array_dskwrite_data, struct message_content_t, PER_CPU_ENTRIES);
BPF_PERCPU_ARRAY(percpu_array_file_info, struct file_info_t, PER_CPU_ENTRIES);
BPF_PERCPU_ARRAY(per_cpu_aux, struct dentries_data_t, 1);

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

int static to_discard(struct file_info_t *fi) {
    int i, j, key, flag;

    if (fi->pipe_no != -1) return 1;

    if (fi->filename_len == 3)
		if (fi->filename[0] == 'T' && fi->filename[1] == 'C' && fi->filename[2] == 'P')
			return 1;

    if (WHITELIST_SIZE <= 0) return 0;
    for (i = 0; i < WHITELIST_SIZE; i++) {
        key = i;
        struct whitelist_entry_t *whitename = whitelist_array.lookup(&key);
        if (!whitename) return 0;

        if (fi->filename_len >= whitename->size) {
            flag = 0;
            for(j = 0; j < whitename->size; j++) {
                if (j >= fi->filename_len) break;
                if (j >= 60) break;
                if ( whitename->name[j] != fi->filename[j]) { flag = 1; break; }
            }
            if (flag == 0) return 0;
        }
    }

    return 1;
}

void static delete_auxiliar_data(struct temp_key_t key) {
    if (is_socket_event(key.type)) sock_handlers.delete(&key);
    if (is_disk_event(key.type)) {
        kiocb_handlers.delete(&key);
        file_data_handlers.delete(&key);
        fd_handlers.delete(&key);
    }
    iovec_handlers.delete(&key);
    entry_timestamps.delete(&key);
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


// Checks if fd is a standard fd
static int handle_standard_fd(struct file_info_t *fi, u64 fd) {
    char stdin[5] = "STDIN";
    char stdout[6] = "STDOUT";
    char stderr[6] = "STDERR";
    if (fd == 0) {
        bpf_probe_read(&fi->filename, 5, &stdin);
        fi->filename_len = 5;
    } else if (fd == 1) {
        bpf_probe_read(&fi->filename, 6, &stdout);
        fi->filename_len = 6;
    } else if (fd == 2) {
        bpf_probe_read(&fi->filename, 6, &stderr);
        fi->filename_len = 6;
    } else return 0;
    return 1;
}

static struct file* get_file_from_fd(unsigned int fd) {
    struct files_struct *files = NULL;
    struct fdtable *fdtable = NULL;
    struct file **fileptr = NULL;
    struct file *file = NULL;
    // struct path path;
    // struct dentry *dentry;
    struct task_struct *curr_task = (struct task_struct *) bpf_get_current_task();

    bpf_probe_read(&files, sizeof(files), &curr_task->files);
    bpf_probe_read(&fdtable, sizeof(fdtable), &files->fdt);
    bpf_probe_read(&fileptr, sizeof(fileptr), &fdtable->fd);
    bpf_probe_read(&file, sizeof(file), &fileptr[fd]);
    // bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);
    // dentry = path.dentry;

    return file;
}

static struct file* get_file_from_kiocv(struct kiocb *iocb) {
    struct file* file = NULL;
    struct path path;
    bpf_probe_read(&file, sizeof(file), &iocb->ki_filp);
    return file;
}

static struct dentry* get_dentry_from_file(struct file *file) {
    struct path path;
    struct dentry* dentry = NULL;

    if (file) {
        bpf_probe_read(&path, sizeof(path), (const void*)&file->f_path);
        dentry = path.dentry;
    }
    return dentry;
}

// fill in information about the file
static int get_filename(struct dentry *dentry, struct file_info_t *fi) {

    if (!dentry) return -1;

    char sepchar = '/';
    char nulchar = '\0';

    int i = 0, key = 0;
    u32 n_bytes = 0, len = 0;
    unsigned short file_type;
    struct inode *inode = NULL;
    struct dentry dtry;
    struct dentry *lastdtryp = NULL;

    bpf_probe_read(&inode, sizeof(struct inode*), &dentry->d_inode);
    if (!inode) return -1;

    bpf_probe_read(&file_type, sizeof(file_type), &inode->i_mode);
    unsigned short ft = (file_type) & S_IFMT;

    if (ft == S_IFIFO) {
        bpf_probe_read(&fi->pipe_no, sizeof(fi->pipe_no), &inode->i_ino);
        return 0;
    }  else {

        struct dentries_data_t *dentries = per_cpu_aux.lookup(&key);
        if (!dentries) return -1;

        bpf_probe_read(&dtry, sizeof(struct dentry), dentry);
        lastdtryp = dentry;

        // bpf_trace_printk("Sizeof dentry: %d\n", sizeof(struct qstr));

        u32 n_dentries = 0;
        for (i = 0; i < (FILENAME_MAX/SUB_STR_MAX); i++) {
            if (i < 0 || i >= (FILENAME_MAX/SUB_STR_MAX)) break;

            bpf_probe_read(&dentries->qstr_array[i], sizeof(struct qstr), (const void*)&dtry.d_name);
            struct dentry* parent = dtry.d_parent;
            if (dentry) {
                struct qstr qp;
                bpf_probe_read(&qp, sizeof(struct qstr), &parent->d_name);
            }
            n_dentries += 1;

            if (dtry.d_parent != lastdtryp) {
                lastdtryp = dtry.d_parent;
                bpf_probe_read(&dtry, sizeof(struct dentry), dtry.d_parent);
            } else break;
        }

        n_bytes = 0;
        for (i = (n_dentries - 1); i >= 0; i--) {
            if (i < 0 || i >= (FILENAME_MAX/SUB_STR_MAX)) break;

            len = dentries->qstr_array[i].len;
            if (len < 0) len = 0;
            if (len >= SUB_STR_MAX) len = SUB_STR_MAX;
            if (n_bytes > (FILENAME_MAX-SUB_STR_MAX)) break;
            if (n_bytes < 0) break;

            bpf_probe_read(&fi->filename[n_bytes], len, dentries->qstr_array[i].name);
            n_bytes += len;

            if ((i < (n_dentries-1))) {
                if ((n_bytes < 0) || (n_bytes >= FILENAME_MAX)) break;
                if (i == 0) bpf_probe_read(&fi->filename[n_bytes], 1, &nulchar);
                else {
                    fi->filename[n_bytes] = '/';
                    bpf_probe_read(&fi->filename[n_bytes], 1, &sepchar);
                    n_bytes++;
                }
            }
        }
        fi->filename_len = n_bytes;
    }
    return 0;

}

// fill in the extra data (socket_info or file_info)
static int get_file_info(struct file_info_t *fi, struct temp_key_t key, int is_syscall) {
    int result = 0;

    struct file* file = NULL;
    struct dentry *dentry;
    fi->pipe_no = -1;

    if (is_syscall) {
        u64 *fd = fd_handlers.lookup(&key);
        if (!fd) return -1;
        fi->fd = *fd;
        if (handle_standard_fd(fi, *fd) == 1)
        {
            if (to_discard(fi) == 1) return -2;
            return 0;
        }

        file = get_file_from_fd(*fd);
        if (!file) return -1;
    } else {
        // struct kiocb *iocb = kiocb_handlers.lookup(&pid);;
        // if (!iocb) return -1;

        // file = get_file_from_kiocv(iocb);
        // if (!file) return -1;

        // fi->fd = 0;
    }

    dentry = get_dentry_from_file(file);
    if (!dentry) return -1;

    result = get_filename(dentry, fi);
    if (result != 0) return -1;

    if (to_discard(fi) == 1) return -2;


    return 0;
}

// fill in information about the socket
struct socket_info_t static get_socket_info(struct sock * skp, short type) {
    u16 sport = 0;
    u16 dport = 0;
    u16 family = 0;
    struct socket_info_t sk = {};

    bpf_probe_read(&family, sizeof(family), &skp->sk_family);

    if (family == AF_INET) {
        u32 saddr = 0;
        u32 daddr = 0;

        bpf_probe_read(&saddr, sizeof(saddr), &skp->sk_rcv_saddr);
        bpf_probe_read(&daddr, sizeof(daddr), &skp->sk_daddr);

        sk.saddr[1] = saddr;
        sk.daddr[1] = daddr;
    } else if (family == AF_INET6) {
        bpf_probe_read(sk.saddr, sizeof(sk.saddr), &skp->sk_v6_rcv_saddr);
        bpf_probe_read(sk.daddr, sizeof(sk.daddr), &skp->sk_v6_daddr);
    }

    bpf_probe_read(&sport, sizeof(sport), &skp->sk_num);
    bpf_probe_read(&dport, sizeof(dport), &skp->sk_dport);

    sk.sport = sport;
    sk.dport = ntohs(dport);
    sk.family = family;
    sk.type = type;

    return sk;
}

// copy data from struct iov_iter to struct event_data_t
static inline size_t copy_data_from_iov(struct message_content_t *event, size_t len, const struct iov_iter* aux_data) {

    int read_res = 0;
    size_t iov_len = 0;

    //if (len < 0) len = 0;
    //if (len >= MAX_BUF_SIZE) len = MAX_BUF_SIZE;

    if (len > 0) {
        const struct iovec *aux_data_iov = aux_data->iov;

        size_t offset;
        read_res = bpf_probe_read(&offset, sizeof(offset), &aux_data->iov_offset);
        if(read_res != 0) return -1;

        char *aux_buf;
        read_res = bpf_probe_read(&aux_buf, sizeof(&aux_buf), &aux_data_iov->iov_base + offset);
        if(read_res != 0) return -1;

        read_res = bpf_probe_read(&event->msg, len, aux_buf);     // copy buf into scratch space
        if(read_res != 0) return -1;

        bpf_probe_read(&iov_len, sizeof(iov_len), &aux_data_iov->iov_len);
    }
    return iov_len;
}
// --------------------

void static emit_disk_event(struct pt_regs *ctx, struct pid_info_t proc_info, u64 timestamp, int bytes, enum event_type e_type, int is_iov)
{

	struct event_context_t context = {};
	context.etype = e_type;
    context.pid = proc_info.kpid;
    context.tgid = proc_info.tgid;
    context.ktime = timestamp;
    bpf_get_current_comm(&context.comm, sizeof(context.comm));

    struct temp_key_t key = {
        .type = e_type,
        .pid = proc_info.kpid
    };

    struct event_disk_t disk_info = {};
    disk_info.context = context;

	// ----- Get index

	u64 event_ref = incrementIndexCounter();
    disk_info.index = (event_ref % PER_CPU_ENTRIES);
    disk_info.n_ref = event_ref;
    disk_info.cpu = bpf_get_smp_processor_id();

	// ----- Get File Info

    struct file_info_t *fi = NULL;
    if (is_disk_event(e_type)) {
        fi = percpu_array_file_info.lookup(&disk_info.index);
        if (fi != NULL) {
            int res = get_file_info(fi, key, (is_iov == 1) ? 0 : 1);
            if (res == -2) return;
            if (res == 0) {
				fi->n_ref = event_ref;
				if (e_type == DSK_OPEN) fi->offset = -1;
			}
        }
    }

    if (e_type == DSK_OPEN) {
        int sub_res = events.perf_submit(ctx, &disk_info, sizeof(disk_info));
        if (sub_res == 0) incrementExitCounter(e_type);
        else incrementLostCounter(e_type);

    }
    else { // ----- Get Message

        struct event_disk_data_t event = {};
        event.disk_info = disk_info;
        event.size = bytes;
        event.returned_value = bytes;

		struct message_content_t* content = percpu_array_dskwrite_data.lookup(&disk_info.index);
		if (!content) return;

        size_t len = bytes;
        if (len < 0) len = 0;
        if (len >= MAX_BUF_SIZE) len = MAX_BUF_SIZE;
        content->msg_len = len;
        content->n_ref = disk_info.n_ref;

        if (is_iov == 1) {
            // const struct iov_iter* iov_data = iovec_handlers.lookup(&key);
            // if (!iov_data) return; // if no slot found, bailm
            // size_t read_data = copy_data_from_iov(data, len, iov_data);
            // if (read_data < 0) return;
            // bpf_probe_read(&event.size, sizeof(event.size), &read_data);
        }
        else {
            struct wr_rd_file_data_t *buffer_data = file_data_handlers.lookup(&key);
            if (!buffer_data) return;

            int read_data = bpf_probe_read(&(content->msg), len, buffer_data->buf);     // copy buf into scratch space
            if (read_data != 0) return;

            bpf_probe_read(&event.size, sizeof(event.size), &buffer_data->count);
            if (fi != NULL) bpf_probe_read(&fi->offset, sizeof(fi->offset), &buffer_data->offset);
        }

        int sub_res = events.perf_submit(ctx, &event, sizeof(event));
        if (sub_res == 0) incrementExitCounter(e_type);
        else incrementLostCounter(e_type);
    }

}

void static emit_socket_event(struct pt_regs *ctx, struct pid_info_t proc_info, u64 timestamp, int bytes, enum event_type e_type)
{

	struct event_context_t context = {};
	context.etype = e_type;
    context.pid = proc_info.kpid;
    context.tgid = proc_info.tgid;
    context.ktime = timestamp;
    bpf_get_current_comm(&context.comm, sizeof(context.comm));

    struct temp_key_t key = {
        .type = e_type,
        .pid = proc_info.kpid,
    };

    struct event_socket_t socket_info = {};
    socket_info.context = context;

    // ----- Get Socket Info

    struct socket_entry_info_t * socket = sock_handlers.lookup(&key);
    if (!socket) return;

    struct socket_info_t sk = get_socket_info(socket->sk, socket->type);
    socket_info.socket = sk;

    if (sk.family != AF_INET && sk.family != AF_INET6)
        return;

    if (e_type == SOCKET_CONNECT || e_type == SOCKET_SEND || e_type == SOCKET_RECEIVE) {
        if (socket_info.socket.dport == 53 || socket_info.socket.dport == 9092) return;
    }

    if (e_type == SOCKET_SEND || e_type ==  SOCKET_RECEIVE) {

        struct event_socket_data_t event = {};
        event.socket_info = socket_info;

        // ----- Get index

        u64 event_ref = incrementIndexCounter();
        event.index = (event_ref % PER_CPU_ENTRIES);
        event.n_ref = event_ref;
        event.cpu = bpf_get_smp_processor_id();

        // ----- Get Message

        event.size = bytes;
        event.returned_value = bytes;

        struct message_content_t* content = percpu_array_dskwrite_data.lookup(&event.index);
        if (!content) return;

        size_t len = bytes;
        if (len < 0) len = 0;
        if (len >= MAX_BUF_SIZE) len = MAX_BUF_SIZE;
        content->msg_len = len;
        content->n_ref = event.n_ref;

        const struct iov_iter* iov_data = iovec_handlers.lookup(&key);
        if (!iov_data) return; // if no slot found, bailm
        size_t read_data = copy_data_from_iov(content, len, iov_data);
        if (read_data < 0) return;
        bpf_probe_read(&event.size, sizeof(event.size), &read_data);

        int sub_res = events.perf_submit(ctx, &event, sizeof(event));
        if (sub_res == 0) incrementExitCounter(e_type);
        else incrementLostCounter(e_type);

    }
    else {
        int sub_res = events.perf_submit(ctx, &socket_info, sizeof(socket_info));
        if (sub_res == 0) incrementExitCounter(e_type);
        else incrementLostCounter(e_type);
    }

}

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

    struct temp_key_t key = {
        .type = DSK_WRITE,
        .pid = proc_info.kpid
    };

	// increment enter_sys_write counter //TODO
	incrementEnterCounter(DSK_WRITE);

	u64 timestamp = bpf_ktime_get_ns();
	entry_timestamps.update(&key, &timestamp);

	struct wr_rd_file_data_t aux_data = {};
    bpf_probe_read(&aux_data.buf, sizeof(aux_data.buf), &args->buf);
    bpf_probe_read(&aux_data.count, sizeof(aux_data.count), &args->count);
    aux_data.offset = -1;
    file_data_handlers.update(&key, &aux_data);

    u64 fd;
    bpf_probe_read(&fd, sizeof(fd), &args->fd);
    fd_handlers.update(&key, &fd);

	return 0;
}

int exit__sys_write(struct sys_exit_wr_rd_args *args) {
	struct pid_info_t proc_info = pid_info();
	if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_WRITE,
        .pid = proc_info.kpid
    };

	u64 *timestamp = entry_timestamps.lookup(&key);
	int write_bytes = args->ret;

	if (write_bytes >= 0 && timestamp != NULL)
	{
		emit_disk_event((struct pt_regs *)args, proc_info, *timestamp, write_bytes, DSK_WRITE, 0);
	}
	else if (write_bytes < 0)
	{
		// Something went wrong.
		incrementErrorCounter(DSK_WRITE);
	}

	delete_auxiliar_data(key);

	return 0;
}

int enter_sys_pwrite64(struct sys_enter_wr_rd_args *args) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_WRITE,
        .pid = proc_info.kpid
    };

    // increment enter_sys_write counter //TODO
    incrementEnterCounter(DSK_WRITE);

    u64 timestamp = bpf_ktime_get_ns();
	entry_timestamps.update(&key, &timestamp);


    struct wr_rd_file_data_t aux_data = {};
    bpf_probe_read(&aux_data.buf, sizeof(aux_data.buf), &args->buf);
    bpf_probe_read(&aux_data.count, sizeof(aux_data.count), &args->count);
    bpf_probe_read(&aux_data.offset, sizeof(aux_data.offset), &args->pos);
    file_data_handlers.update(&key, &aux_data);

    u64 fd;
    bpf_probe_read(&fd, sizeof(fd), &args->fd);
    fd_handlers.update(&key, &fd);

    return 0;
}

int exit_sys_pwrite64(struct sys_exit_wr_rd_args *args) {
	struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_WRITE,
        .pid = proc_info.kpid
    };

    u64 *timestamp = entry_timestamps.lookup(&key);
	int write_bytes = args->ret;

	if (write_bytes >= 0 && timestamp != NULL)
	{
        emit_disk_event((struct pt_regs *)args, proc_info, *timestamp, write_bytes, DSK_WRITE, 0);
    }
    else if (write_bytes < 0)
    {
        // Something went wrong.
        incrementErrorCounter(DSK_WRITE);
    }

    delete_auxiliar_data(key);

    return 0;
}

int entry__sys_read(struct sys_enter_wr_rd_args *args)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_READ,
        .pid = proc_info.kpid
    };

    // increment enter_sys_read counter //TODO
    incrementEnterCounter(DSK_READ);

    struct wr_rd_file_data_t aux_data = {};
    bpf_probe_read(&aux_data.buf, sizeof(aux_data.buf), &args->buf);
    bpf_probe_read(&aux_data.count, sizeof(aux_data.count), &args->count);
    aux_data.offset = -1;
    file_data_handlers.update(&key, &aux_data);

    u64 fd;
    bpf_probe_read(&fd, sizeof(fd), &args->fd);
    fd_handlers.update(&key, &fd);

    return 0;
}

int exit__sys_read(struct sys_exit_wr_rd_args *args)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_READ,
        .pid = proc_info.kpid
    };

    u64 timestamp = bpf_ktime_get_ns();
    long read_bytes = args->ret;

    if (read_bytes >= 0)
    {
        emit_disk_event((struct pt_regs *)args, proc_info, timestamp, read_bytes, DSK_READ, 0);
    }
    else if (read_bytes < 0)
    {
        // Something went wrong.
        incrementErrorCounter(DSK_READ);
    }

    delete_auxiliar_data(key);

    return 0;
}

int enter_sys_pread64(struct sys_enter_wr_rd_args *args) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_READ,
        .pid = proc_info.kpid
    };

    // increment enter_sys_read counter //TODO
    incrementEnterCounter(DSK_READ);

    struct wr_rd_file_data_t aux_data = {};
    bpf_probe_read(&aux_data.buf, sizeof(aux_data.buf), &args->buf);
    bpf_probe_read(&aux_data.count, sizeof(aux_data.count), &args->count);
    bpf_probe_read(&aux_data.offset, sizeof(aux_data.offset), &args->pos);
    file_data_handlers.update(&key, &aux_data);

    u64 fd;
    bpf_probe_read(&fd, sizeof(fd), &args->fd);
    fd_handlers.update(&key, &fd);

    return 0;
}

int exit_sys_pread64(struct sys_exit_wr_rd_args *args) {
	struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_READ,
        .pid = proc_info.kpid
    };

    u64 timestamp = bpf_ktime_get_ns();
    long read_bytes = args->ret;

    if (read_bytes >= 0)
    {
        emit_disk_event((struct pt_regs *)args, proc_info, timestamp, read_bytes, DSK_READ, 0);
    }
    else if (read_bytes < 0)
    {
        // Something went wrong.
        incrementErrorCounter(DSK_READ);
    }

    delete_auxiliar_data(key);

    return 0;
}

long entry__do_sys_open(struct pt_regs *ctx,  int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_OPEN,
        .pid = proc_info.kpid
    };

    // increment entry__do_sys_open counter
    incrementEnterCounter(DSK_OPEN);

    u64 timestamp = bpf_ktime_get_ns();
    entry_timestamps.update(&key, &timestamp);

    return 0;
}

long exit__do_sys_open(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = DSK_OPEN,
        .pid = proc_info.kpid
    };

    u64 *timestamp = entry_timestamps.lookup(&key);
    long file_descriptor = PT_REGS_RC(ctx);

    if (file_descriptor >= 0 && timestamp != NULL)
    {
        fd_handlers.update(&key, (u64*) &file_descriptor);
        emit_disk_event(ctx, proc_info, *timestamp, 0, DSK_OPEN, 0);
    }
    else if (file_descriptor < 0)
    {
        // Something went wrong.
        incrementErrorCounter(DSK_OPEN);
    }

    entry_timestamps.delete(&key);

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

    struct temp_key_t key = {
        .type = SOCKET_CONNECT,
        .pid = proc_info.kpid
    };

    incrementEnterCounter(SOCKET_CONNECT);

    u64 timestamp = bpf_ktime_get_ns();
    entry_timestamps.update(&key, &timestamp);

    // Stash the current sock for the exit call.
    struct socket_entry_info_t sock_info = {};
    sock_info.sk = sk;
    sock_info.type = SOCK_DGRAM;
    sock_handlers.update(&key, &sock_info);

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

    struct temp_key_t key = {
        .type = SOCKET_CONNECT,
        .pid = proc_info.kpid
    };

    incrementEnterCounter(SOCKET_CONNECT);

    u64 timestamp = bpf_ktime_get_ns();
    entry_timestamps.update(&key, &timestamp);

    // Stash the current sock for the exit call.
    struct socket_entry_info_t sock_info = {};
    sock_info.sk = sk;
    sock_info.type = SOCK_STREAM;
    sock_handlers.update(&key, &sock_info);

    return 0;
}

/**
 * Probe "connect" at the exit point.
 */
int exit__connect(struct pt_regs *ctx) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = SOCKET_CONNECT,
        .pid = proc_info.kpid
    };

    int error = PT_REGS_RC(ctx);
    u64 *timestamp = entry_timestamps.lookup(&key);

    if (error >= 0 && timestamp != NULL) {
        emit_socket_event(ctx, proc_info, *timestamp, 0, SOCKET_CONNECT);
    } else if (error < 0 ) {
        // Something went wrong, so do not register socket.
        incrementErrorCounter(SOCKET_CONNECT);
    }

    delete_auxiliar_data(key);

    return 0;
}

/**
 * Probe "inet_csk_accept" at the exit point.
 */
int exit__inet_csk_accept(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = SOCKET_ACCEPT,
        .pid = proc_info.kpid
    };

    u64 timestamp = bpf_ktime_get_ns();

    struct sock * skp = (struct sock *) PT_REGS_RC(ctx);
    if (skp != NULL)
    {
        struct socket_entry_info_t sock_info = {};
        sock_info.sk = skp;
        sock_info.type = SOCK_STREAM;
        sock_handlers.update(&key, &sock_info);
        emit_socket_event(ctx, proc_info, timestamp, 0, SOCKET_ACCEPT);
    }

    delete_auxiliar_data(key);

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

    struct temp_key_t key = {
        .type = SOCKET_SEND,
        .pid = proc_info.kpid
    };

    incrementEnterCounter(SOCKET_SEND);

    u64 timestamp = bpf_ktime_get_ns();
    entry_timestamps.update(&key, &timestamp);

    // Stash the current sock for the exit call.
    struct socket_entry_info_t sock_info = {};
    sock_info.sk = sock->sk;
    sock_info.type = sock->type;
    sock_handlers.update(&key, &sock_info);

    const struct iov_iter iov_data = msg->msg_iter;
    iovec_handlers.update(&key, &iov_data);

    return 0;
}

/**
 * Probe "sock_sendmsg" at the exit point.
 */
int exit__sock_sendmsg(struct pt_regs *ctx) {
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = SOCKET_SEND,
        .pid = proc_info.kpid
    };

    int sent_bytes = PT_REGS_RC(ctx);
    u64 *timestamp = entry_timestamps.lookup(&key);

    if (sent_bytes >= 0 && timestamp != NULL) {
        emit_socket_event(ctx, proc_info, *timestamp, sent_bytes, SOCKET_SEND);
    } else if (sent_bytes < 0 ) {
        // Something went wrong.
        incrementErrorCounter(SOCKET_SEND);
    }

    delete_auxiliar_data(key);

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

    struct temp_key_t key = {
        .type = SOCKET_RECEIVE,
        .pid = proc_info.kpid
    };

    // increment entry__sock_recvmsg counter
    incrementEnterCounter(SOCKET_RECEIVE);

    // Stash the current sock for the exit call.
    struct socket_entry_info_t sock_info = {};
    sock_info.sk = sock->sk;
    sock_info.type = sock->type;
    sock_handlers.update(&key, &sock_info);


    const struct iov_iter iov_data = msg->msg_iter;
    iovec_handlers.update(&key, &iov_data);

    return 0;
}

/**
 * Probe "sock_recvmsg" at the exit point.
 */
int exit__sock_recvmsg(struct pt_regs *ctx)
{
    struct pid_info_t proc_info = pid_info();
    if (skip(proc_info)) return 1;

    struct temp_key_t key = {
        .type = SOCKET_RECEIVE,
        .pid = proc_info.kpid
    };

    int read_bytes = PT_REGS_RC(ctx);
    u64 timestamp = bpf_ktime_get_ns();

    if (read_bytes >= 0 )
    {
        emit_socket_event(ctx, proc_info, timestamp, read_bytes, SOCKET_RECEIVE);
    }
    else if (read_bytes < 0)
    {
        // Something went wrong.
        incrementErrorCounter(SOCKET_RECEIVE);
    }

    delete_auxiliar_data(key);

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