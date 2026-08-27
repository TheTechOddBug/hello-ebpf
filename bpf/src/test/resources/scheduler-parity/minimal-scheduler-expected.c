#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

s64 _exitCode SEC(".data");
s64 _exitKind SEC(".data");

#define PF_KTHREAD 2097152

__always_inline bool hasSchedulingConstraints(struct task_struct *p);

__always_inline bool isDescendantOf(struct task_struct *p, s32 targetTgid);

__always_inline bool isMigrationDisabled(struct task_struct *p);

__always_inline s64 scaleByTaskWeight(struct task_struct *p, s64 value);

__always_inline int dsqInsert(struct task_struct *p, s64 enq_flags);

__always_inline s32 selectCpuDfl(struct task_struct *p, s32 prev_cpu, s64 wake_flags);

__always_inline s32 selectCpuFifoIdleOrFallback(struct task_struct *p, s32 prev_cpu, s64 wake_flags, u64 dsqId);

__always_inline bool isSmaller(u64 a, u64 b);

__always_inline int vtimeCharge(struct task_struct *p);


#define SHARED_DSQ_ID 0L



char _license[] SEC("license") = "GPL";

SEC("struct_ops.s/init") s32 BPF_PROG(sched_init) {
  #line 73 "SchedulerBase.java"
  return scx_bpf_create_dsq(SHARED_DSQ_ID, -1);
}

SEC("struct_ops/dispatch") void BPF_PROG(sched_dispatch, s32 cpu, struct task_struct *prev) {
  #line 44 "MinimalScheduler.java"
  scx_bpf_dsq_move_to_local(SHARED_DSQ_ID);
}

SEC("struct_ops/enqueue") void BPF_PROG(sched_enqueue, struct task_struct *p, __u64 enq_flags) {
  #line 39 "MinimalScheduler.java"
  scx_bpf_dsq_insert(p, SHARED_DSQ_ID, scx_bpf_dsq_nr_queued(SHARED_DSQ_ID) > 0   ? SCX_SLICE_DFL / (u64)scx_bpf_dsq_nr_queued(SHARED_DSQ_ID)   : SCX_SLICE_DFL, enq_flags);
}

SEC("struct_ops/exit") void BPF_PROG(sched_exit, struct scx_exit_info *ei) {
  #line 82 "SchedulerBase.java"
  _exitCode = BPF_CORE_READ(ei, exit_code);
  #line 83 "SchedulerBase.java"
  _exitKind = (s64)(long)(BPF_CORE_READ(ei, kind));
}
#define SHARED_DSQ_ID 0L

SEC(".struct_ops.link")
struct sched_ext_ops sched_ops = {
    .enqueue = (void *)sched_enqueue,
    .dispatch = (void *)sched_dispatch,
    .init = (void *)sched_init,
    .exit = (void *)sched_exit,
    .timeout_ms = 10000,
    .name = "minimal_scheduler",
    .flags = SCX_OPS_ENQ_LAST | SCX_OPS_KEEP_BUILTIN_IDLE | (0),
};
