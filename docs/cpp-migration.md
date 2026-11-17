# isolate — C/C++ Migration Guide

This document describes how to reimplement isolate in C/C++ if you need to:
- Integrate with an existing C/C++ codebase or kernel module
- Eliminate the Rust toolchain dependency in embedded / bare-metal environments
- Maximise compile-time control (link-time optimisation, `-Os` firmware images)
- Author kernel modules that expose isolate-equivalent functionality

---

## 1. Why you might migrate

| Reason | Notes |
|--------|-------|
| Kernel module requirements | Rust in the kernel (since 6.1) is still limited; complex module logic is easier in C |
| FFI overhead | If most code is already C, thin Rust wrappers add latency |
| Toolchain constraints | Some secure-boot / HSM environments mandate GCC-only build chains |
| Existing C codebase | Integrating with a C-based hypervisor or security agent |

In all other cases, the Rust implementation is preferred for memory safety reasons.

---

## 2. Core equivalents

### `isolate-core` → `isolate.h`

```c
// isolate.h — core types

#include <stdint.h>
#include <stddef.h>

// Isobox identifier (26-char ULID string + null terminator)
typedef struct { char id[27]; } isobox_id_t;

// Workload class
typedef enum {
    WORKLOAD_CUSTOM            = 0,
    WORKLOAD_MALWARE_ANALYSIS  = 1,
    WORKLOAD_MICROSERVICE      = 2,
    WORKLOAD_DEV_ENVIRONMENT   = 3,
    WORKLOAD_COMPROMISED       = 4,
} workload_class_t;

// Policy default action
typedef enum {
    POLICY_AUDIT = 0,
    POLICY_BLOCK = 1,
    POLICY_KILL  = 2,
} policy_action_t;

// Error codes
typedef enum {
    ISOLATE_OK          =  0,
    ISOLATE_ERR_CONFIG  = -1,
    ISOLATE_ERR_POLICY  = -2,
    ISOLATE_ERR_BACKEND = -3,
    ISOLATE_ERR_INTEL   = -4,
    ISOLATE_ERR_STORE   = -5,
    ISOLATE_ERR_IPC     = -6,
    ISOLATE_ERR_AUTH    = -7,
    ISOLATE_ERR_PALADIN = -8,
} isolate_err_t;
```

### `SandboxBackend` trait → function pointer vtable

```c
// backend.h — SandboxBackend vtable

typedef struct sandbox_handle sandbox_handle_t;
typedef struct isobox_config  isobox_config_t;
typedef struct policy_update  policy_update_t;

struct sandbox_backend_ops {
    const char *name;
    int         priority;   // higher = applied first
    int       (*is_available)(void);
    int       (*create)(isobox_id_t id, const isobox_config_t *cfg,
                        sandbox_handle_t **out_handle);
    int       (*freeze)(sandbox_handle_t *handle);
    int       (*thaw)(sandbox_handle_t *handle);
    int       (*snapshot)(sandbox_handle_t *handle, const char *path);
    int       (*apply_policy)(sandbox_handle_t *handle,
                              const policy_update_t *update);
    int       (*destroy)(sandbox_handle_t *handle);
    int       (*kill_immediate)(sandbox_handle_t *handle);
};

// Register a backend
void sandbox_backend_register(const struct sandbox_backend_ops *ops);

// Get all available backends sorted by priority
int sandbox_backends_available(const struct sandbox_backend_ops **out, int max);
```

### `tokio` async → `libuv` or `io_uring` + `epoll`

The Rust implementation uses `tokio` for async I/O. C equivalents:

| Tokio feature | C equivalent |
|--------------|-------------|
| `tokio::spawn` | `pthread_create` or `libuv` tasks |
| `tokio::select!` | `epoll_wait` / `io_uring` |
| `tokio::sync::broadcast` | Custom MPMC ring buffer + eventfd |
| `tokio::time::interval` | `timerfd_create` + `epoll` |
| `tokio::net::TcpListener` | POSIX sockets + `epoll` |

Recommended C async framework: **libuv** (battle-tested, cross-platform).
For Linux-specific highest performance: **io_uring** via `liburing`.

### `aya` eBPF → `libbpf`

```c
// Load and attach eBPF programs using libbpf-bootstrap pattern

#include <bpf/libbpf.h>
#include "syscall_monitor.skel.h"

struct syscall_monitor_bpf *skel = syscall_monitor_bpf__open();
syscall_monitor_bpf__load(skel);
syscall_monitor_bpf__attach(skel);

// Read ring buffer
struct ring_buffer *rb = ring_buffer__new(
    bpf_map__fd(skel->maps.events),
    handle_event,
    NULL, NULL
);
ring_buffer__poll(rb, 100 /* ms */);
```

### `axum` REST → `libmicrohttpd` or `mongoose`

For a minimal REST server in C:

```c
#include <microhttpd.h>

static enum MHD_Result
handle_request(void *cls, struct MHD_Connection *conn,
               const char *url, const char *method, ...)
{
    if (strcmp(url, "/api/v1/isoboxes") == 0 &&
        strcmp(method, "GET") == 0)
    {
        const char *json = list_isoboxes_json();
        struct MHD_Response *resp =
            MHD_create_response_from_buffer(strlen(json),
                (void *)json, MHD_RESPMEM_MUST_COPY);
        return MHD_queue_response(conn, MHD_HTTP_OK, resp);
    }
    return MHD_NO;
}

struct MHD_Daemon *d = MHD_start_daemon(
    MHD_USE_THREAD_PER_CONNECTION,
    7778, NULL, NULL, &handle_request, NULL, MHD_OPTION_END);
```

Alternative: **mongoose** (embedded HTTP + WebSocket, single-file).

### `tonic` gRPC → `grpc-c`

```c
#include <grpc/grpc.h>
#include <grpc/support/log.h>
// Generated stub from proto files:
#include "isolate.grpc.pb.h"

// Server implementation pattern (C++ bindings are more ergonomic)
```

Note: The gRPC C core library (`libgrpc`) is complex to build from scratch.
Consider using the C++ bindings (simpler) or `grpc-c` (smaller footprint).

### `ratatui` TUI → `ncurses` / `notcurses`

```c
#include <ncurses.h>

WINDOW *isobox_list = newwin(LINES - 2, 30, 1, 0);
WINDOW *syscall_graph = newwin(LINES - 2, COLS - 30, 1, 30);

// Draw isobox list
wattron(isobox_list, COLOR_PAIR(1));
mvwprintw(isobox_list, 1, 2, "%-24s %s", "NAME", "STATE");
// ... etc
```

`notcurses` is more modern and supports full RGB, Unicode, and pixel graphics.

### `ort` ONNX → `onnxruntime` C API

```c
#include <onnxruntime_c_api.h>

const OrtApi *g_ort = OrtGetApiBase()->GetApi(ORT_API_VERSION);

OrtEnv *env;
g_ort->CreateEnv(ORT_LOGGING_LEVEL_WARNING, "isolate", &env);

OrtSession *session;
OrtSessionOptions *opts;
g_ort->CreateSessionOptions(&opts);
g_ort->CreateSession(env, L"behavior_classifier_v1.onnx", opts, &session);

// Run inference
float input_data[FEATURE_VEC_LEN] = { ... };
OrtValue *input_tensor, *output_tensor;
// ... (allocate tensors, run, extract score)
```

### `sqlx`/SQLite → `sqlite3.h`

```c
#include <sqlite3.h>

sqlite3 *db;
sqlite3_open("/var/lib/isolate/isolate.db", &db);

// Enable WAL mode
sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

// Prepared statement pattern
sqlite3_stmt *stmt;
sqlite3_prepare_v2(db,
    "INSERT INTO events(isobox_id, timestamp_ns, body_json) VALUES (?,?,?)",
    -1, &stmt, NULL);
sqlite3_bind_text(stmt, 1, isobox_id, -1, SQLITE_STATIC);
sqlite3_bind_int64(stmt, 2, timestamp_ns);
sqlite3_bind_text(stmt, 3, body_json, -1, SQLITE_STATIC);
sqlite3_step(stmt);
sqlite3_finalize(stmt);
```

---

## 3. Build system

### CMakeLists.txt skeleton

```cmake
cmake_minimum_required(VERSION 3.20)
project(isolate C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies (via pkg-config or vcpkg)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)
pkg_check_modules(LIBUV REQUIRED libuv)

# Core library
add_library(isolate-core STATIC
    src/core/id.c
    src/core/config.c
    src/core/error.c
)

# Daemon
add_executable(isolatd
    src/daemon/main.c
    src/daemon/rest.c
    src/daemon/supervisor.c
    src/daemon/grpc.c
)
target_link_libraries(isolatd isolate-core
    ${LIBBPF_LIBRARIES} ${SQLITE3_LIBRARIES} ${LIBUV_LIBRARIES}
    pthread dl)

# Paladin (minimal deps)
add_executable(isolate-paladin
    src/paladin/main.c
    src/paladin/escalation.c
    src/paladin/watchdog.c
    src/paladin/sentinel.c
)
target_link_libraries(isolate-paladin pthread)
```

---

## 4. Memory safety compensations

When replacing Rust's ownership model with manual C memory management:

| Rust guarantee | C compensation |
|----------------|----------------|
| No use-after-free | ASAN in debug builds, valgrind memcheck in CI |
| No buffer overflows | ASAN, `-fsanitize=bounds`, fuzz with AFL++ |
| No data races | TSan (`-fsanitize=thread`), lock discipline annotations |
| No null pointer deref | Mandatory null checks, `-fsanitize=null` |
| No integer overflow | `-fsanitize=integer`, explicit range checks |

Recommended CI additions:
```bash
# AddressSanitizer + UBSan
gcc -fsanitize=address,undefined -g -O1 ...

# ThreadSanitizer (for concurrent code)
gcc -fsanitize=thread -g -O1 ...

# Fuzzing with AFL++
afl-fuzz -i seeds/ -o findings/ -- ./isolatd-fuzz @@
```

---

## 5. Platform-specific notes per backend

### Linux eBPF (libbpf)

- Use `libbpf-bootstrap` skeleton generation for CO-RE programs
- The `.bpf.c` files in `ebpf/` are already C — no changes needed
- Userspace loader replaces `aya` with `libbpf` API calls
- Ring buffer: `ring_buffer__new` + `ring_buffer__poll` (replaces aya RingBuf)

### macOS ESF (C API)

```c
#include <EndpointSecurity/EndpointSecurity.h>

es_client_t *client = NULL;
es_new_client(&client, ^(es_client_t *c, const es_message_t *msg) {
    switch (msg->event_type) {
        case ES_EVENT_TYPE_AUTH_EXEC:
            // Authorize or deny
            es_respond_auth_result(c, msg, ES_AUTH_RESULT_ALLOW, false);
            break;
        default: break;
    }
});

es_event_type_t events[] = {
    ES_EVENT_TYPE_AUTH_EXEC,
    ES_EVENT_TYPE_AUTH_OPEN,
    ES_EVENT_TYPE_NOTIFY_FORK,
};
es_subscribe(client, events, sizeof(events)/sizeof(events[0]));
```

### Windows ETW (C)

```c
#include <evntrace.h>
#include <evntcons.h>

// Open a real-time ETW trace session
TRACEHANDLE session;
EVENT_TRACE_PROPERTIES props = { .Wnode.BufferSize = sizeof(props), ... };
StartTrace(&session, L"IsolateTrace", &props);

// Register a provider callback
EnableTraceEx2(session, &providerGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, ...);

// Process events
ProcessTrace(&session, 1, NULL, NULL);
```

---

## 6. Paladin in C (minimal implementation)

The paladin has minimal dependencies by design. The C equivalent:

```c
// paladin/escalation.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/sysrq.h>

typedef enum {
    LEVEL_WATCHING  = 0,
    LEVEL_ALERT     = 1,
    LEVEL_CONTAIN   = 2,
    LEVEL_FREEZE    = 3,
    LEVEL_TERMINATE = 4,
    LEVEL_SCORCH    = 5,
    LEVEL_RAMPART   = 6,
    LEVEL_ABSOLUTION = 7,
} escalation_level_t;

int escalate(const char *isobox_id, int cgroup_fd,
             escalation_level_t level)
{
    switch (level) {
    case LEVEL_CONTAIN:
        // nft rule: drop all traffic from/to cgroup
        return system("nft add rule inet isolate-filter forward "
                      "meta cgroup <id> drop");
    case LEVEL_FREEZE:
        // Write "1" to cgroup.freeze
        write(cgroup_fd, "1", 1);
        return 0;
    case LEVEL_TERMINATE:
        // Write "1" to cgroup.kill
        write(cgroup_fd, "1", 1);
        return 0;
    case LEVEL_ABSOLUTION:
        // Last resort: sysrq
        if (getenv("PALADIN_ABSOLUTION_ENABLED")) {
            FILE *f = fopen("/proc/sysrq-trigger", "w");
            if (f) { fputc('s', f); fclose(f); } // sync
            f = fopen("/proc/sysrq-trigger", "w");
            if (f) { fputc('u', f); fclose(f); } // remount RO
            f = fopen("/proc/sysrq-trigger", "w");
            if (f) { fputc('c', f); fclose(f); } // crash
        }
        return 0;
    default:
        return -1;
    }
}
```
