/*
 * DetHV Deterministic In-Memory Loopback Network, Epoll, and TimerFD Stack
 *
 * Provides 100% deterministic virtual networking (AF_INET/AF_INET6 UDP & TCP,
 * AF_UNIX socketpair/stream), epoll (including EPOLLET/EPOLLONESHOT), and
 * timerfd driven solely by vm->det.vmono_ns — zero host sockets, zero port
 * collisions, zero wall-clock timing jitter!
 */

#include "internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/un.h>

int net_init(dethv_vm_t *vm) {
    net_state_t *n = &vm->net;
    memset(n, 0, sizeof(*n));
    n->sockets = calloc(DETHV_MAX_SOCKETS, sizeof(vsock_t));
    n->epolls  = calloc(DETHV_MAX_EPOLLS,  sizeof(vepoll_t));
    n->timers  = calloc(DETHV_MAX_TIMERS,  sizeof(vtimer_t));
    n->tx_q    = calloc(DETHV_NET_TX_QUEUE_LEN, sizeof(dethv_udp_pkt_t));
    if (!n->sockets || !n->epolls || !n->timers || !n->tx_q) return -1;
    for (int i = 0; i < DETHV_MAX_SOCKETS; i++) n->sockets[i].peer_sock = -1;
    n->next_ephemeral_port = 40000;
    return 0;
}

static void free_socket_buffers(vsock_t *s) {
    for (uint32_t i = 0; i < s->udp_count; i++) {
        uint32_t idx = (s->udp_head + i) % DETHV_UDP_QUEUE_LEN;
        free(s->udp_q[idx].data);
        s->udp_q[idx].data = NULL;
    }
    s->udp_count = 0;
    s->udp_head = 0;
    free(s->stream_buf);
    s->stream_buf = NULL;
    s->stream_count = s->stream_read = s->stream_write = 0;
}

void net_destroy(net_state_t *net) {
    if (net->sockets) {
        for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
            if (net->sockets[i].used) free_socket_buffers(&net->sockets[i]);
        }
        free(net->sockets);
        net->sockets = NULL;
    }
    free(net->epolls); net->epolls = NULL;
    free(net->timers); net->timers = NULL;
    free(net->tx_q);   net->tx_q   = NULL;
}

int net_clone(net_state_t *dst, const net_state_t *src) {
    if (!dst->sockets) dst->sockets = calloc(DETHV_MAX_SOCKETS, sizeof(vsock_t));
    if (!dst->epolls)  dst->epolls  = calloc(DETHV_MAX_EPOLLS,  sizeof(vepoll_t));
    if (!dst->timers)  dst->timers  = calloc(DETHV_MAX_TIMERS,  sizeof(vtimer_t));
    if (!dst->sockets || !dst->epolls || !dst->timers) return -1;

    for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
        if (dst->sockets[i].used) free_socket_buffers(&dst->sockets[i]);
        dst->sockets[i].used = false;
        if (!src->sockets || !src->sockets[i].used) continue;

        vsock_t *d = &dst->sockets[i];
        const vsock_t *s = &src->sockets[i];
        *d = *s;
        memset(d->udp_q, 0, sizeof(d->udp_q));
        d->stream_buf = NULL;

        for (uint32_t k = 0; k < s->udp_count; k++) {
            uint32_t idx = (s->udp_head + k) % DETHV_UDP_QUEUE_LEN;
            d->udp_q[idx] = s->udp_q[idx];
            d->udp_q[idx].data = NULL;
            if (s->udp_q[idx].len > 0 && s->udp_q[idx].data) {
                d->udp_q[idx].data = malloc(s->udp_q[idx].len);
                if (!d->udp_q[idx].data) return -1;
                memcpy(d->udp_q[idx].data, s->udp_q[idx].data, s->udp_q[idx].len);
            }
        }
        if (s->stream_buf) {
            d->stream_buf = malloc(DETHV_STREAM_BUF_SIZE);
            if (!d->stream_buf) return -1;
            memcpy(d->stream_buf, s->stream_buf, DETHV_STREAM_BUF_SIZE);
        }
    }

    if (src->epolls) memcpy(dst->epolls, src->epolls, DETHV_MAX_EPOLLS * sizeof(vepoll_t));
    if (src->timers) memcpy(dst->timers, src->timers, DETHV_MAX_TIMERS * sizeof(vtimer_t));
    dst->next_ephemeral_port = src->next_ephemeral_port;
    dst->dirty = false;
    dst->tx_head = 0;
    dst->tx_count = 0;
    return 0;
}

int net_restore(net_state_t *dst, const net_state_t *src) {
    uint32_t saved_guest_ip = dst->guest_ip;
    uint32_t saved_peer_ip  = dst->peer_ip;
    int rc = net_clone(dst, src);
    dst->guest_ip = saved_guest_ip;
    dst->peer_ip  = saved_peer_ip;
    return rc;
}

void dethv_net_set_peer_ip(dethv_vm_t *vm, uint32_t guest_ip_host_order, uint32_t peer_ip_host_order) {
    vm->net.guest_ip = guest_ip_host_order;
    vm->net.peer_ip  = peer_ip_host_order;
}

int dethv_net_inject_udp(dethv_vm_t *vm,
                         uint32_t src_ip, uint16_t src_port,
                         uint32_t dst_ip, uint16_t dst_port,
                         const void *data, size_t len) {
    vsock_t *dst = NULL;
    for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
        vsock_t *cand = &vm->net.sockets[i];
        if (!cand->used || !cand->bound || cand->type != SOCK_DGRAM || cand->local_port != dst_port)
            continue;
        if (cand->local_ip == dst_ip) {
            dst = cand;
            break;
        }
        if (!dst) dst = cand;
    }
    if (!dst) return -1;
    if (dst->udp_count >= DETHV_UDP_QUEUE_LEN) return -1;

    uint32_t tail = (dst->udp_head + dst->udp_count) % DETHV_UDP_QUEUE_LEN;
    udp_pkt_t *pkt = &dst->udp_q[tail];
    pkt->src_ip   = src_ip;
    pkt->src_port = src_port;
    pkt->is_ipv6  = 0;
    pkt->len      = (uint32_t)len;
    pkt->data     = len > 0 ? malloc(len) : NULL;
    if (len > 0) {
        if (!pkt->data) return -1;
        memcpy(pkt->data, data, len);
    }
    dst->udp_count++;
    dst->io_gen++;
    vm->net.dirty = true;
    net_wake_io_waiters(vm);
    return 0;
}

int dethv_net_pop_tx(dethv_vm_t *vm, dethv_udp_pkt_t *out) {
    if (!vm->net.tx_q || vm->net.tx_count == 0) return 0;
    if (out) *out = vm->net.tx_q[vm->net.tx_head];
    vm->net.tx_head = (vm->net.tx_head + 1) % DETHV_NET_TX_QUEUE_LEN;
    vm->net.tx_count--;
    return 1;
}

size_t dethv_net_get_bound_udp_ports(const dethv_vm_t *vm, uint16_t *ports_out, size_t max_ports) {
    size_t cnt = 0;
    for (int i = 0; i < DETHV_MAX_SOCKETS && cnt < max_ports; i++) {
        const vsock_t *s = &vm->net.sockets[i];
        if (s->used && s->bound && s->type == SOCK_DGRAM) {
            bool dup = false;
            for (size_t k = 0; k < cnt; k++) {
                if (ports_out[k] == s->local_port) { dup = true; break; }
            }
            if (!dup) ports_out[cnt++] = s->local_port;
        }
    }
    return cnt;
}

static int alloc_socket_slot(dethv_vm_t *vm) {
    for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
        if (!vm->net.sockets[i].used) {
            vsock_t *s = &vm->net.sockets[i];
            memset(s, 0, sizeof(*s));
            s->used = true;
            s->refcount = 1;
            s->peer_sock = -1;
            s->rcvbuf_sz = 262144;
            s->sndbuf_sz = 262144;
            vm->net.dirty = true;
            return i;
        }
    }
    return -ENFILE;
}

static uint16_t alloc_ephemeral_port(dethv_vm_t *vm, int type) {
    for (int tries = 0; tries < 20000; tries++) {
        uint16_t port = vm->net.next_ephemeral_port++;
        if (vm->net.next_ephemeral_port >= 60000) vm->net.next_ephemeral_port = 40000;
        bool clash = false;
        for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
            vsock_t *s = &vm->net.sockets[i];
            if (s->used && s->bound && s->type == type && s->local_port == port) {
                clash = true;
                break;
            }
        }
        if (!clash) return port;
    }
    return vm->net.next_ephemeral_port++;
}

static bool parse_sockaddr(const void *addr, uint32_t addrlen, int *fam_out, uint32_t *ip_out, uint16_t *port_out) {
    if (!addr || addrlen < 2) return false;
    uint16_t fam = 0;
    memcpy(&fam, addr, 2);
    *fam_out = fam;
    if (fam == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
        *ip_out   = ntohl(in->sin_addr.s_addr);
        *port_out = ntohs(in->sin_port);
        return true;
    }
    if (fam == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
        *port_out = ntohs(in6->sin6_port);
        /* Map :: / ::1 / ::ffff:127.0.0.1 to 127.0.0.1 loopback */
        static const uint8_t v4map[12] = {0,0,0,0, 0,0,0,0, 0,0,0xff,0xff};
        if (memcmp(in6->sin6_addr.s6_addr, v4map, 12) == 0) {
            uint32_t raw;
            memcpy(&raw, in6->sin6_addr.s6_addr + 12, 4);
            *ip_out = ntohl(raw);
        } else {
            bool all_zero = true;
            for (int i = 0; i < 16; i++) if (in6->sin6_addr.s6_addr[i]) all_zero = false;
            *ip_out = all_zero ? 0 : 0x7F000001U;
        }
        return true;
    }
    if (fam == AF_UNIX) {
        *ip_out = 0x7F000001U;
        *port_out = 0;
        return true;
    }
    return false;
}

static void write_sockaddr(int domain, uint32_t ip, uint16_t port, void *addr_out, uint32_t *addrlen_inout) {
    if (!addr_out || !addrlen_inout) return;
    if (domain == AF_INET6) {
        struct sockaddr_in6 in6;
        memset(&in6, 0, sizeof(in6));
        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(port);
        if (ip == 0) {
            /* :: */
        } else if (ip == 0x7F000001U) {
            in6.sin6_addr.s6_addr[15] = 1; /* ::1 */
        } else {
            in6.sin6_addr.s6_addr[10] = 0xff;
            in6.sin6_addr.s6_addr[11] = 0xff;
            uint32_t nip = htonl(ip);
            memcpy(in6.sin6_addr.s6_addr + 12, &nip, 4);
        }
        uint32_t copy = *addrlen_inout < sizeof(in6) ? *addrlen_inout : (uint32_t)sizeof(in6);
        memcpy(addr_out, &in6, copy);
        *addrlen_inout = sizeof(in6);
    } else if (domain == AF_INET) {
        struct sockaddr_in in;
        memset(&in, 0, sizeof(in));
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        in.sin_addr.s_addr = htonl(ip);
        uint32_t copy = *addrlen_inout < sizeof(in) ? *addrlen_inout : (uint32_t)sizeof(in);
        memcpy(addr_out, &in, copy);
        *addrlen_inout = sizeof(in);
    } else if (domain == AF_UNIX) {
        struct sockaddr_un un;
        memset(&un, 0, sizeof(un));
        un.sun_family = AF_UNIX;
        uint32_t copy = *addrlen_inout < 2 ? *addrlen_inout : 2;
        memcpy(addr_out, &un, copy);
        *addrlen_inout = 2;
    }
}

void net_wake_io_waiters(dethv_vm_t *vm) {
    for (int i = 0; i < (int)vm->sched.used_slots; i++) {
        guest_thread_t *t = &vm->sched.threads[i];
        if (t->state == THREAD_BLOCKED_IO) {
            t->state = THREAD_RUNNABLE;
            t->branch_budget = vm->cfg.preempt_quantum;
        }
    }
}

void net_close_socket(dethv_vm_t *vm, uint32_t sidx) {
    if (sidx >= DETHV_MAX_SOCKETS || !vm->net.sockets[sidx].used) return;
    vsock_t *s = &vm->net.sockets[sidx];
    if (--s->refcount > 0) return;

    if (s->peer_sock >= 0 && s->peer_sock < DETHV_MAX_SOCKETS && vm->net.sockets[s->peer_sock].used) {
        vsock_t *peer = &vm->net.sockets[s->peer_sock];
        peer->peer_closed = true;
        peer->peer_sock = -1;
        peer->io_gen++;
        net_wake_io_waiters(vm);
    }
    free_socket_buffers(s);
    s->used = false;
    vm->net.dirty = true;
}

void net_close_epoll(dethv_vm_t *vm, uint32_t eidx) {
    if (eidx < DETHV_MAX_EPOLLS) { vm->net.epolls[eidx].used = false; vm->net.dirty = true; }
}

void net_close_timer(dethv_vm_t *vm, uint32_t tidx) {
    if (tidx < DETHV_MAX_TIMERS) { vm->net.timers[tidx].used = false; vm->net.dirty = true; }
}

uint64_t net_earliest_timer_ns(const dethv_vm_t *vm) {
    uint64_t earliest = UINT64_MAX;
    for (int i = 0; i < DETHV_MAX_TIMERS; i++) {
        const vtimer_t *tm = &vm->net.timers[i];
        if (tm->used && tm->next_expire_ns > 0 && tm->next_expire_ns < earliest) {
            earliest = tm->next_expire_ns;
        }
    }
    return earliest;
}

/* Unified poll/epoll readiness check for any FD */
uint32_t net_fd_poll_events(dethv_vm_t *vm, int fd) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return POLLNVAL;
    vfd_t *f = &vm->vfs.fds[fd];
    uint32_t ev = 0;

    switch (f->kind) {
        case FD_STDIN:
            ev |= EPOLLIN;
            break;
        case FD_STDOUT:
        case FD_STDERR:
        case FD_DEV_NULL:
            ev |= EPOLLOUT;
            break;
        case FD_DEV_ZERO:
        case FD_DEV_URANDOM:
        case FD_MEM_VFILE:
        case FD_PROC_VFILE:
        case FD_HOST_RO:
            ev |= EPOLLIN | EPOLLOUT;
            break;
        case FD_PIPE_READ: {
            vpipe_t *p = &vm->vfs.pipes[f->ref_idx];
            if (p->count > 0) ev |= EPOLLIN;
            if (p->write_closed) ev |= EPOLLIN | EPOLLHUP;
            break;
        }
        case FD_PIPE_WRITE: {
            vpipe_t *p = &vm->vfs.pipes[f->ref_idx];
            if (p->read_closed) ev |= EPOLLERR | EPOLLHUP;
            else if (p->count < DETHV_PIPE_BUF_SIZE) ev |= EPOLLOUT;
            break;
        }
        case FD_EVENTFD:
            if (f->eventfd_val > 0) ev |= EPOLLIN;
            ev |= EPOLLOUT;
            break;
        case FD_TIMERFD: {
            vtimer_t *tm = &vm->net.timers[f->ref_idx];
            if (tm->used && tm->next_expire_ns > 0 && vm->det.vmono_ns >= tm->next_expire_ns) {
                ev |= EPOLLIN;
            }
            break;
        }
        case FD_SOCKET: {
            vsock_t *s = &vm->net.sockets[f->ref_idx];
            if (!s->used) return POLLNVAL;
            if (s->type == SOCK_DGRAM) {
                if (s->udp_count > 0) ev |= EPOLLIN;
                ev |= EPOLLOUT;
            } else if (s->type == SOCK_STREAM) {
                if (s->listening) {
                    if (s->accept_count > 0) ev |= EPOLLIN;
                } else {
                    if (s->stream_count > 0) ev |= EPOLLIN;
                    if (s->peer_closed || s->shut_rd) ev |= EPOLLIN | EPOLLRDHUP | EPOLLHUP;
                    if (s->connected && !s->shut_wr && !s->peer_closed) {
                        if (s->peer_sock >= 0 && vm->net.sockets[s->peer_sock].stream_count < DETHV_STREAM_BUF_SIZE)
                            ev |= EPOLLOUT;
                    } else if (s->peer_closed) {
                        ev |= EPOLLOUT | EPOLLHUP;
                    }
                }
            }
            break;
        }
        default:
            break;
    }
    return ev;
}

int net_sys_socket(dethv_vm_t *vm, int domain, int type, int protocol) {
    int base_type = type & 0xFF;
    if (domain != AF_INET && domain != AF_INET6 && domain != AF_UNIX && domain != AF_NETLINK) {
        return -EAFNOSUPPORT;
    }
    if (domain == AF_NETLINK) {
        return -EAFNOSUPPORT; /* Forces libc/Rust to cleanly skip netlink interface enumeration */
    }
    if (base_type != SOCK_DGRAM && base_type != SOCK_STREAM) {
        return -ESOCKTNOSUPPORT;
    }

    int sidx = alloc_socket_slot(vm);
    if (sidx < 0) return sidx;
    int fd = vfs_alloc_fd(&vm->vfs, 0);
    if (fd < 0) {
        vm->net.sockets[sidx].used = false;
        return fd;
    }

    vsock_t *s = &vm->net.sockets[sidx];
    s->domain   = domain;
    s->type     = base_type;
    s->protocol = protocol;
    if (base_type == SOCK_STREAM) {
        s->stream_buf = malloc(DETHV_STREAM_BUF_SIZE);
        if (!s->stream_buf) { s->used = false; return -ENOMEM; }
    }

    int fd_flags = O_RDWR;
    if (type & SOCK_NONBLOCK) fd_flags |= O_NONBLOCK;
    if (type & SOCK_CLOEXEC)  fd_flags |= O_CLOEXEC;

    vfd_t *f = &vm->vfs.fds[fd];
    memset(f, 0, sizeof(*f));
    f->used = true;
    f->kind = FD_SOCKET;
    f->flags = fd_flags;
    f->host_fd = -1;
    f->ref_idx = (uint32_t)sidx;
    snprintf(f->path, sizeof(f->path), "socket:[%d]", sidx);
    vm->vfs.fds_dirty = true;
    return fd;
}

int net_sys_socketpair(dethv_vm_t *vm, int domain, int type, int protocol, int sv_out[2]) {
    int fd0 = net_sys_socket(vm, domain, type, protocol);
    if (fd0 < 0) return fd0;
    int fd1 = net_sys_socket(vm, domain, type, protocol);
    if (fd1 < 0) { vfs_close(vm, fd0); return fd1; }

    int s0 = (int)vm->vfs.fds[fd0].ref_idx;
    int s1 = (int)vm->vfs.fds[fd1].ref_idx;
    vm->net.sockets[s0].connected = true;
    vm->net.sockets[s0].peer_sock = s1;
    vm->net.sockets[s1].connected = true;
    vm->net.sockets[s1].peer_sock = s0;
    sv_out[0] = fd0;
    sv_out[1] = fd1;
    return 0;
}

int net_sys_bind(dethv_vm_t *vm, int fd, const void *addr, uint32_t addrlen) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    int fam = 0; uint32_t ip = 0; uint16_t port = 0;
    if (!parse_sockaddr(addr, addrlen, &fam, &ip, &port)) return -EINVAL;

    if (port == 0 && (fam == AF_INET || fam == AF_INET6)) {
        port = alloc_ephemeral_port(vm, s->type);
    } else if (port != 0 && !s->reuseport) {
        /* Check if port already bound by another socket of same type without SO_REUSEPORT */
        for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
            vsock_t *o = &vm->net.sockets[i];
            if (o != s && o->used && o->bound && o->type == s->type && o->local_port == port) {
                if (!(s->reuseaddr && o->reuseaddr && !o->listening)) {
                    return -EADDRINUSE;
                }
            }
        }
    }

    s->bound      = true;
    s->local_ip   = (ip == 0) ? (vm->net.guest_ip ? vm->net.guest_ip : 0x7F000001U) : ip;
    s->local_port = port;
    vm->net.dirty = true;
    return 0;
}

int net_sys_listen(dethv_vm_t *vm, int fd, int backlog) {
    (void)backlog;
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    if (s->type != SOCK_STREAM) return -EOPNOTSUPP;
    if (!s->bound) {
        s->bound = true;
        s->local_ip = 0x7F000001U;
        s->local_port = alloc_ephemeral_port(vm, SOCK_STREAM);
    }
    s->listening = true;
    return 0;
}

int net_sys_connect(dethv_vm_t *vm, int fd, const void *addr, uint32_t addrlen) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    int fam = 0; uint32_t ip = 0; uint16_t port = 0;
    if (!parse_sockaddr(addr, addrlen, &fam, &ip, &port)) return -EINVAL;

    if (!s->bound) {
        s->bound = true;
        s->local_ip = 0x7F000001U;
        s->local_port = alloc_ephemeral_port(vm, s->type);
    }

    if (s->type == SOCK_DGRAM) {
        /* UDP connect simply sets default peer address */
        s->connected = true;
        s->peer_ip   = (ip == 0) ? 0x7F000001U : ip;
        s->peer_port = port;
        return 0;
    }

    /* TCP connect: find listening socket on target port */
    vsock_t *listener = NULL;
    for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
        vsock_t *cand = &vm->net.sockets[i];
        if (cand->used && cand->listening && cand->type == SOCK_STREAM && cand->local_port == port) {
            listener = cand;
            break;
        }
    }
    if (!listener) return -ECONNREFUSED;
    if (listener->accept_count >= 64) return -ECONNREFUSED;

    /* Create server-side connected socket immediately */
    int srv_idx = alloc_socket_slot(vm);
    if (srv_idx < 0) return -ENFILE;
    vsock_t *srv = &vm->net.sockets[srv_idx];
    srv->domain     = listener->domain;
    srv->type       = SOCK_STREAM;
    srv->bound      = true;
    srv->connected  = true;
    srv->local_ip   = listener->local_ip;
    srv->local_port = listener->local_port;
    srv->peer_ip    = s->local_ip;
    srv->peer_port  = s->local_port;
    srv->peer_sock  = (int32_t)vm->vfs.fds[fd].ref_idx;
    srv->stream_buf = malloc(DETHV_STREAM_BUF_SIZE);
    if (!srv->stream_buf) { srv->used = false; return -ENOMEM; }

    s->connected = true;
    s->peer_ip   = listener->local_ip;
    s->peer_port = listener->local_port;
    s->peer_sock = srv_idx;

    uint32_t tail = (listener->accept_head + listener->accept_count) % 64;
    listener->accept_q[tail] = srv_idx;
    listener->accept_count++;
    listener->io_gen++;
    s->io_gen++;
    net_wake_io_waiters(vm);
    return 0;
}

int net_sys_accept(dethv_vm_t *vm, int fd, void *addr_out, uint32_t *addrlen_inout, int flags) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    if (!s->listening) return -EINVAL;
    if (s->accept_count == 0) return -EAGAIN;

    int srv_idx = s->accept_q[s->accept_head];
    s->accept_head = (s->accept_head + 1) % 64;
    s->accept_count--;

    int new_fd = vfs_alloc_fd(&vm->vfs, 0);
    if (new_fd < 0) {
        net_close_socket(vm, (uint32_t)srv_idx);
        return new_fd;
    }

    int fd_flags = O_RDWR;
    if (flags & SOCK_NONBLOCK) fd_flags |= O_NONBLOCK;
    if (flags & SOCK_CLOEXEC)  fd_flags |= O_CLOEXEC;

    vfd_t *nf = &vm->vfs.fds[new_fd];
    memset(nf, 0, sizeof(*nf));
    nf->used    = true;
    nf->kind    = FD_SOCKET;
    nf->flags   = fd_flags;
    nf->host_fd = -1;
    nf->ref_idx = (uint32_t)srv_idx;
    snprintf(nf->path, sizeof(nf->path), "socket:[%d]", srv_idx);
    vm->vfs.fds_dirty = true;

    vsock_t *srv = &vm->net.sockets[srv_idx];
    write_sockaddr(srv->domain, srv->peer_ip, srv->peer_port, addr_out, addrlen_inout);
    return new_fd;
}

int net_sys_getsockname(dethv_vm_t *vm, int fd, void *addr_out, uint32_t *addrlen_inout, bool peer) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    if (peer) {
        if (!s->connected) return -ENOTCONN;
        write_sockaddr(s->domain, s->peer_ip, s->peer_port, addr_out, addrlen_inout);
    } else {
        write_sockaddr(s->domain, s->bound ? s->local_ip : 0, s->bound ? s->local_port : 0, addr_out, addrlen_inout);
    }
    return 0;
}

int net_sys_setsockopt(dethv_vm_t *vm, int fd, int level, int optname, const void *optval, uint32_t optlen) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    if (level == SOL_SOCKET) {
        if (optname == SO_RCVTIMEO && optlen >= sizeof(struct timeval)) {
            const struct timeval *tv = (const struct timeval *)optval;
            s->rcvtimeo_ns = (uint64_t)tv->tv_sec * 1000000000ULL + (uint64_t)tv->tv_usec * 1000ULL;
        } else if (optname == SO_SNDTIMEO && optlen >= sizeof(struct timeval)) {
            const struct timeval *tv = (const struct timeval *)optval;
            s->sndtimeo_ns = (uint64_t)tv->tv_sec * 1000000000ULL + (uint64_t)tv->tv_usec * 1000ULL;
        } else if (optname == SO_REUSEADDR && optlen >= 4) {
            int v = 0; memcpy(&v, optval, 4); s->reuseaddr = (v != 0);
        } else if (optname == SO_REUSEPORT && optlen >= 4) {
            int v = 0; memcpy(&v, optval, 4); s->reuseport = (v != 0);
        } else if (optname == SO_RCVBUF && optlen >= 4) {
            int v = 0; memcpy(&v, optval, 4); if (v > 0) s->rcvbuf_sz = v;
        } else if (optname == SO_SNDBUF && optlen >= 4) {
            int v = 0; memcpy(&v, optval, 4); if (v > 0) s->sndbuf_sz = v;
        }
    } else if (level == IPPROTO_IP && optname == IP_PKTINFO && optlen >= 4) {
        int v = 0; memcpy(&v, optval, 4); s->recv_pktinfo = (v != 0);
    } else if (level == IPPROTO_IPV6 && optname == IPV6_RECVPKTINFO && optlen >= 4) {
        int v = 0; memcpy(&v, optval, 4); s->recv_pktinfo = (v != 0);
    } else if (level == IPPROTO_IPV6 && optname == IPV6_V6ONLY && optlen >= 4) {
        int v = 0; memcpy(&v, optval, 4); s->ipv6_only = (v != 0);
    } else if (level == IPPROTO_UDP && (optname == 103 || optname == 104)) {
        /* Disable UDP_SEGMENT (GSO) & UDP_GRO so quinn-udp uses clean single-datagram I/O */
        return -ENOPROTOOPT;
    }
    return 0;
}

int net_sys_getsockopt(dethv_vm_t *vm, int fd, int level, int optname, void *optval, uint32_t *optlen_inout) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    int val = 0;
    if (level == SOL_SOCKET) {
        if (optname == SO_ERROR)     val = 0;
        else if (optname == SO_TYPE) val = s->type;
        else if (optname == SO_RCVBUF) val = s->rcvbuf_sz;
        else if (optname == SO_SNDBUF) val = s->sndbuf_sz;
        else if (optname == SO_ACCEPTCONN) val = s->listening ? 1 : 0;
    }
    uint32_t len = *optlen_inout < 4 ? *optlen_inout : 4;
    if (optval && len > 0) memcpy(optval, &val, len);
    *optlen_inout = 4;
    return 0;
}

int net_sys_shutdown(dethv_vm_t *vm, int fd, int how) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];
    if (how == SHUT_RD || how == SHUT_RDWR) s->shut_rd = true;
    if (how == SHUT_WR || how == SHUT_RDWR) {
        s->shut_wr = true;
        if (s->peer_sock >= 0 && vm->net.sockets[s->peer_sock].used) {
            vm->net.sockets[s->peer_sock].peer_closed = true;
            vm->net.sockets[s->peer_sock].io_gen++;
        }
    }
    net_wake_io_waiters(vm);
    return 0;
}

int64_t net_sys_sendto(dethv_vm_t *vm, int fd, const void *buf, size_t len, int flags,
                       const void *dest_addr, uint32_t addrlen) {
    (void)flags;
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vsock_t *s = &vm->net.sockets[vm->vfs.fds[fd].ref_idx];

    if (s->type == SOCK_STREAM) {
        if (!s->connected || s->peer_sock < 0) return -ENOTCONN;
        if (s->peer_closed || s->shut_wr) return -EPIPE;
        vsock_t *peer = &vm->net.sockets[s->peer_sock];
        if (!peer->used || !peer->stream_buf) return -EPIPE;
        uint32_t space = DETHV_STREAM_BUF_SIZE - peer->stream_count;
        if (space == 0) return -EAGAIN;
        size_t n = len < space ? len : space;
        const uint8_t *src = (const uint8_t *)buf;
        for (size_t i = 0; i < n; i++) {
            peer->stream_buf[peer->stream_write] = src[i];
            peer->stream_write = (peer->stream_write + 1) % DETHV_STREAM_BUF_SIZE;
            peer->stream_count++;
        }
        peer->io_gen++;
        net_wake_io_waiters(vm);
        return (int64_t)n;
    }

    /* UDP sendto */
    if (!s->bound) {
        s->bound = true;
        s->local_ip = vm->net.guest_ip ? vm->net.guest_ip : 0x7F000001U;
        s->local_port = alloc_ephemeral_port(vm, SOCK_DGRAM);
        vm->net.dirty = true;
    }

    uint32_t dst_ip = s->peer_ip;
    uint16_t dst_port = s->peer_port;
    if (dest_addr && addrlen > 0) {
        int fam = 0;
        if (!parse_sockaddr(dest_addr, addrlen, &fam, &dst_ip, &dst_port))
            return -EINVAL;
    } else if (!s->connected) {
        return -EDESTADDRREQ;
    }

    /* External virtual peer bridge: route UDP packets targeting peer_ip to host TX queue! */
    if (vm->net.peer_ip != 0 && dst_ip == vm->net.peer_ip && vm->net.tx_q) {
        if (vm->net.tx_count < DETHV_NET_TX_QUEUE_LEN) {
            uint32_t tail = (vm->net.tx_head + vm->net.tx_count) % DETHV_NET_TX_QUEUE_LEN;
            dethv_udp_pkt_t *tp = &vm->net.tx_q[tail];
            uint32_t src_ip = s->local_ip ? s->local_ip : (vm->net.guest_ip ? vm->net.guest_ip : 0x7F000001U);
            if (src_ip == 0x7F000001U && vm->net.guest_ip) src_ip = vm->net.guest_ip;
            tp->src_ip   = src_ip;
            tp->src_port = s->local_port;
            tp->dst_ip   = dst_ip;
            tp->dst_port = dst_port;
            tp->vmono_ns = vm->det.vmono_ns;
            size_t copy = len <= sizeof(tp->data) ? len : sizeof(tp->data);
            tp->len = (uint32_t)copy;
            if (copy > 0) memcpy(tp->data, buf, copy);
            vm->net.tx_count++;
        }
        if (vm->stop_on_net_tx) {
            vm->running = false;
            vm->stop_reason = DETHV_STOP_NET_TX;
        }
        return (int64_t)len;
    }

    /* Deliver deterministically to matching bound UDP socket(s) on dst_port */
    vsock_t *dst = NULL;
    for (int i = 0; i < DETHV_MAX_SOCKETS; i++) {
        vsock_t *cand = &vm->net.sockets[i];
        if (cand->used && cand->bound && cand->type == SOCK_DGRAM && cand->local_port == dst_port) {
            dst = cand;
            break;
        }
    }
    if (!dst) {
        /* Standard UDP behavior: silently dropped if nobody listening on port */
        return (int64_t)len;
    }
    if (dst->udp_count >= DETHV_UDP_QUEUE_LEN) {
        /* Queue full: drop packet deterministically */
        return (int64_t)len;
    }

    uint32_t tail = (dst->udp_head + dst->udp_count) % DETHV_UDP_QUEUE_LEN;
    udp_pkt_t *pkt = &dst->udp_q[tail];
    pkt->src_ip   = s->local_ip ? s->local_ip : 0x7F000001U;
    pkt->src_port = s->local_port;
    pkt->is_ipv6  = (s->domain == AF_INET6) ? 1 : 0;
    pkt->len      = (uint32_t)len;
    pkt->data     = len > 0 ? malloc(len) : NULL;
    if (len > 0) {
        if (!pkt->data) return -ENOMEM;
        memcpy(pkt->data, buf, len);
    }
    dst->udp_count++;
    dst->io_gen++;
    net_wake_io_waiters(vm);
    return (int64_t)len;
}

int64_t net_sys_recvfrom(dethv_vm_t *vm, int fd, void *buf, size_t len, int flags,
                         void *src_addr_out, uint32_t *addrlen_inout,
                         bool *would_block, uint64_t *timeout_ns_out) {
    *would_block = false;
    *timeout_ns_out = 0;
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_SOCKET)
        return -ENOTSOCK;
    vfd_t *f = &vm->vfs.fds[fd];
    vsock_t *s = &vm->net.sockets[f->ref_idx];
    bool nonblock = ((f->flags & O_NONBLOCK) != 0) || ((flags & MSG_DONTWAIT) != 0);

    if (s->type == SOCK_STREAM) {
        if (s->stream_count == 0) {
            if (s->peer_closed || s->shut_rd) return 0; /* EOF */
            if (nonblock) return -EAGAIN;
            *would_block = true;
            *timeout_ns_out = s->rcvtimeo_ns;
            return -EAGAIN;
        }
        size_t n = len < s->stream_count ? len : s->stream_count;
        uint8_t *dst = (uint8_t *)buf;
        if (flags & MSG_PEEK) {
            uint32_t pos = s->stream_read;
            for (size_t i = 0; i < n; i++) {
                dst[i] = s->stream_buf[pos];
                pos = (pos + 1) % DETHV_STREAM_BUF_SIZE;
            }
        } else {
            for (size_t i = 0; i < n; i++) {
                dst[i] = s->stream_buf[s->stream_read];
                s->stream_read = (s->stream_read + 1) % DETHV_STREAM_BUF_SIZE;
                s->stream_count--;
            }
            if (s->peer_sock >= 0 && vm->net.sockets[s->peer_sock].used)
                vm->net.sockets[s->peer_sock].io_gen++;
            net_wake_io_waiters(vm);
        }
        if (src_addr_out && addrlen_inout) {
            write_sockaddr(s->domain, s->peer_ip, s->peer_port, src_addr_out, addrlen_inout);
        }
        return (int64_t)n;
    }

    /* UDP recvfrom */
    if (s->udp_count == 0) {
        if (nonblock) return -EAGAIN;
        *would_block = true;
        *timeout_ns_out = s->rcvtimeo_ns;
        return -EAGAIN;
    }

    udp_pkt_t *pkt = &s->udp_q[s->udp_head];
    size_t copy = len < pkt->len ? len : pkt->len;
    if (copy > 0 && pkt->data) memcpy(buf, pkt->data, copy);
    if (src_addr_out && addrlen_inout) {
        write_sockaddr(s->domain, pkt->src_ip, pkt->src_port, src_addr_out, addrlen_inout);
    }
    int64_t ret = (flags & MSG_TRUNC) ? (int64_t)pkt->len : (int64_t)copy;
    if (!(flags & MSG_PEEK)) {
        free(pkt->data);
        pkt->data = NULL;
        s->udp_head = (s->udp_head + 1) % DETHV_UDP_QUEUE_LEN;
        s->udp_count--;
    }
    return ret;
}

/* ==================== Epoll ==================== */

int net_sys_epoll_create(dethv_vm_t *vm, int flags) {
    int eidx = -1;
    for (int i = 0; i < DETHV_MAX_EPOLLS; i++) {
        if (!vm->net.epolls[i].used) { eidx = i; break; }
    }
    if (eidx < 0) return -EMFILE;
    int fd = vfs_alloc_fd(&vm->vfs, 0);
    if (fd < 0) return fd;

    memset(&vm->net.epolls[eidx], 0, sizeof(vepoll_t));
    vm->net.epolls[eidx].used = true;
    vm->net.dirty = true;

    vfd_t *f = &vm->vfs.fds[fd];
    memset(f, 0, sizeof(*f));
    f->used = true;
    f->kind = FD_EPOLL;
    f->flags = (flags & EPOLL_CLOEXEC) ? O_CLOEXEC : 0;
    f->host_fd = -1;
    f->ref_idx = (uint32_t)eidx;
    snprintf(f->path, sizeof(f->path), "anon_inode:[eventpoll]");
    vm->vfs.fds_dirty = true;
    return fd;
}

int net_sys_epoll_ctl(dethv_vm_t *vm, int epfd, int op, int fd, uint32_t events, uint64_t data) {
    if (epfd < 0 || epfd >= DETHV_MAX_FDS || !vm->vfs.fds[epfd].used || vm->vfs.fds[epfd].kind != FD_EPOLL)
        return -EINVAL;
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vepoll_t *ep = &vm->net.epolls[vm->vfs.fds[epfd].ref_idx];

    int found = -1;
    for (uint32_t i = 0; i < ep->num_watches; i++) {
        if (ep->watches[i].used && ep->watches[i].fd == fd) { found = (int)i; break; }
    }

    if (op == EPOLL_CTL_ADD) {
        if (found >= 0) return -EEXIST;
        if (ep->num_watches >= DETHV_MAX_EPOLL_WATCHES) {
            /* Compact unused entries */
            uint32_t w = 0;
            for (uint32_t i = 0; i < ep->num_watches; i++) {
                if (ep->watches[i].used) ep->watches[w++] = ep->watches[i];
            }
            ep->num_watches = w;
            if (ep->num_watches >= DETHV_MAX_EPOLL_WATCHES) return -ENOSPC;
        }
        ep->watches[ep->num_watches++] = (epoll_watch_t){
            .used = true, .fd = fd, .events = events, .data = data,
            .last_reported = 0, .last_gen = UINT64_MAX
        };
        return 0;
    } else if (op == EPOLL_CTL_MOD) {
        if (found < 0) return -ENOENT;
        ep->watches[found].events        = events;
        ep->watches[found].data          = data;
        ep->watches[found].last_reported = 0;
        ep->watches[found].last_gen      = UINT64_MAX;
        return 0;
    } else if (op == EPOLL_CTL_DEL) {
        if (found < 0) return -ENOENT;
        ep->watches[found].used = false;
        return 0;
    }
    return -EINVAL;
}

static uint64_t get_fd_io_gen(const dethv_vm_t *vm, int fd) {
    const vfd_t *f = &vm->vfs.fds[fd];
    switch (f->kind) {
        case FD_SOCKET:     return vm->net.sockets[f->ref_idx].io_gen;
        case FD_PIPE_READ:
        case FD_PIPE_WRITE: return vm->vfs.pipes[f->ref_idx].io_gen;
        case FD_EVENTFD:    return f->io_gen;
        case FD_TIMERFD:    return vm->net.timers[f->ref_idx].next_expire_ns;
        default:            return f->io_gen;
    }
}

int net_sys_epoll_wait(dethv_vm_t *vm, int epfd, uint64_t events_guest_ptr, int maxevents) {
    if (epfd < 0 || epfd >= DETHV_MAX_FDS || !vm->vfs.fds[epfd].used || vm->vfs.fds[epfd].kind != FD_EPOLL)
        return -EINVAL;
    if (maxevents <= 0) return -EINVAL;
    vepoll_t *ep = &vm->net.epolls[vm->vfs.fds[epfd].ref_idx];

    int ready_cnt = 0;
    for (uint32_t i = 0; i < ep->num_watches && ready_cnt < maxevents; i++) {
        epoll_watch_t *w = &ep->watches[i];
        if (!w->used) continue;
        if (w->fd < 0 || w->fd >= DETHV_MAX_FDS || !vm->vfs.fds[w->fd].used) {
            w->used = false;
            continue;
        }
        uint32_t rev = net_fd_poll_events(vm, w->fd);
        uint32_t matched = rev & (w->events | EPOLLERR | EPOLLHUP);
        uint64_t gen = get_fd_io_gen(vm, w->fd);

        if (w->events & EPOLLET) {
            /* Edge-triggered: only report on newly-rising bits or new I/O event generation! */
            uint32_t new_bits = matched & ~w->last_reported;
            bool new_gen = (matched != 0 && gen != w->last_gen);
            w->last_reported = matched;
            w->last_gen      = gen;
            if (new_bits == 0 && !new_gen) {
                continue;
            }
        }

        if (matched) {
            struct epoll_event ev;
            ev.events   = matched;
            ev.data.u64 = w->data;
            if (mmu_copy_to_guest(vm, events_guest_ptr + (uint64_t)ready_cnt * sizeof(ev), &ev, sizeof(ev)) < 0)
                return -EFAULT;
            if (w->events & EPOLLONESHOT) {
                w->events = 0;
            }
            ready_cnt++;
        }
    }
    return ready_cnt;
}

/* ==================== TimerFD ==================== */

int net_sys_timerfd_create(dethv_vm_t *vm, int clockid, int flags) {
    int tidx = -1;
    for (int i = 0; i < DETHV_MAX_TIMERS; i++) {
        if (!vm->net.timers[i].used) { tidx = i; break; }
    }
    if (tidx < 0) return -EMFILE;
    int fd = vfs_alloc_fd(&vm->vfs, 0);
    if (fd < 0) return fd;

    memset(&vm->net.timers[tidx], 0, sizeof(vtimer_t));
    vm->net.timers[tidx].used = true;
    vm->net.timers[tidx].clockid = clockid;
    vm->net.dirty = true;

    vfd_t *f = &vm->vfs.fds[fd];
    memset(f, 0, sizeof(*f));
    f->used = true;
    f->kind = FD_TIMERFD;
    f->flags = ((flags & TFD_NONBLOCK) ? O_NONBLOCK : 0) | ((flags & TFD_CLOEXEC) ? O_CLOEXEC : 0);
    f->host_fd = -1;
    f->ref_idx = (uint32_t)tidx;
    snprintf(f->path, sizeof(f->path), "anon_inode:[timerfd]");
    vm->vfs.fds_dirty = true;
    return fd;
}

int net_sys_timerfd_settime(dethv_vm_t *vm, int fd, int flags, uint64_t new_val_ns, uint64_t interval_ns, bool abs_time) {
    (void)flags;
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_TIMERFD)
        return -EINVAL;
    vtimer_t *tm = &vm->net.timers[vm->vfs.fds[fd].ref_idx];
    if (new_val_ns == 0) {
        tm->next_expire_ns = 0;
        tm->interval_ns = 0;
    } else {
        tm->next_expire_ns = abs_time ? new_val_ns : (vm->det.vmono_ns + new_val_ns);
        tm->interval_ns = interval_ns;
    }
    return 0;
}

int64_t net_timerfd_read(dethv_vm_t *vm, int fd, uint64_t *exp_out) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used || vm->vfs.fds[fd].kind != FD_TIMERFD)
        return -EINVAL;
    vtimer_t *tm = &vm->net.timers[vm->vfs.fds[fd].ref_idx];
    if (tm->next_expire_ns == 0 || vm->det.vmono_ns < tm->next_expire_ns)
        return -EAGAIN;
    uint64_t exp = 1;
    if (tm->interval_ns > 0) {
        uint64_t over = vm->det.vmono_ns - tm->next_expire_ns;
        exp += over / tm->interval_ns;
        tm->next_expire_ns += exp * tm->interval_ns;
    } else {
        tm->next_expire_ns = 0;
    }
    *exp_out = exp;
    return 8;
}

int net_ioctl(dethv_vm_t *vm, int fd, uint64_t req, uint64_t arg) {
    if (fd < 0 || fd >= DETHV_MAX_FDS || !vm->vfs.fds[fd].used) return -EBADF;
    vfd_t *f = &vm->vfs.fds[fd];
    if (req == FIONBIO) {
        int val = 0;
        if (mmu_copy_from_guest(vm, &val, arg, 4) < 0) return -EFAULT;
        if (val) f->flags |= O_NONBLOCK;
        else     f->flags &= ~O_NONBLOCK;
        return 0;
    }
    if (req == FIOCLEX)  { f->flags |= O_CLOEXEC;  return 0; }
    if (req == FIONCLEX) { f->flags &= ~O_CLOEXEC; return 0; }
    if (req == FIONREAD) {
        int avail = 0;
        if (f->kind == FD_SOCKET) {
            vsock_t *s = &vm->net.sockets[f->ref_idx];
            if (s->type == SOCK_STREAM) avail = (int)s->stream_count;
            else if (s->udp_count > 0)  avail = (int)s->udp_q[s->udp_head].len;
        } else if (f->kind == FD_PIPE_READ) {
            avail = (int)vm->vfs.pipes[f->ref_idx].count;
        }
        return (mmu_copy_to_guest(vm, arg, &avail, 4) == 0) ? 0 : -EFAULT;
    }
    return -ENOTTY;
}
