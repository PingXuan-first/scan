#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/select.h>
#include <fcntl.h>

#define MAX_ITERATIONS 10
#define MAX_PATH 256
#define MAX_CMD 1024
#define TIMEOUT_OTOOL 10
#define TIMEOUT_LLDB 30
#define MAX_THREADS 3

volatile sig_atomic_t interrupted = 0;
bool enable_logging = true;
const char *log_file = "analyze.log";

// 在文件顶部定义 ThreadArgs 结构体
typedef struct {
    const char *binary_path;
    int otool_options;
    const char *lldb_script;
    int pid;
    bool hopper_pseudo;
    bool otool_result;
    bool lldb_result;
    bool hopper_result;
} ThreadArgs;

void log_message(const char *type, const char *message) {
    if (!enable_logging) return;

    FILE *log = fopen(log_file, "a");
    if (!log) {
        fprintf(stderr, "错误：无法打开日志文件 %s (%s)\n", log_file, strerror(errno));
        return;
    }

    time_t now;
    time(&now);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log, "[%s] [%s] %s\n", timestamp, type, message);
    fclose(log);
}

void signal_handler(int sig) {
    interrupted = 1;
    log_message("INFO", "收到中断信号，程序即将退出");
    printf("\n收到中断信号，程序退出...\n");
}

bool compile_c_file(const char *c_file, const char *output_binary) {
    char cmd[MAX_CMD];
    snprintf(cmd, sizeof(cmd), "gcc -o %s %s", output_binary, c_file);
    log_message("INFO", "开始编译 C 文件");
    FILE *pipe = popen(cmd, "r");
    if (!pipe) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "无法执行编译命令: %s (%s)", cmd, strerror(errno));
        log_message("ERROR", err_msg);
        printf("\n错误：无法执行编译命令\n");
        return false;
    }
    char buffer[1024];
    bool success = true;
    while (fgets(buffer, sizeof(buffer), pipe)) {
        printf("%s", buffer);
        success = false;
    }
    int status = pclose(pipe);
    if (success && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        log_message("INFO", "C 文件编译成功");
    } else {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "C 文件编译失败，退出码: %d", WEXITSTATUS(status));
        log_message("ERROR", err_msg);
    }
    return success && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool run_command(const char *cmd, char *output, size_t output_size) {
    log_message("DEBUG", cmd);

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "创建管道失败: %s", strerror(errno));
        log_message("ERROR", err_msg);
        return false;
    }

    pid_t pid = fork();
    if (pid == -1) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "fork 失败: %s", strerror(errno));
        log_message("ERROR", err_msg);
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (pid == 0) { // 子进程
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "execl 失败: %s", strerror(errno));
        log_message("ERROR", err_msg);
        _exit(127);
    }

    close(pipefd[1]);
    FILE *pipe = fdopen(pipefd[0], "r");
    if (!pipe) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "fdopen 失败: %s", strerror(errno));
        log_message("ERROR", err_msg);
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
        return false;
    }

    int fd = fileno(pipe);
    fd_set readfds;
    struct timeval tv;
    tv.tv_sec = TIMEOUT_LLDB;
    tv.tv_usec = 0;
    char buffer[1024];
    bool timed_out = false;
    size_t total_bytes = 0;

    while (!interrupted) {
        FD_ZERO(&readfds);
        FD_SET(fd, &readfds);
        int ready = select(fd + 1, &readfds, NULL, NULL, &tv);
        if (ready < 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "select 失败: %s", strerror(errno));
            log_message("ERROR", err_msg);
            break;
        } else if (ready == 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "命令执行超时: %s", cmd);
            log_message("ERROR", err_msg);
            timed_out = true;
            break;
        }

        if (fgets(buffer, sizeof(buffer), pipe)) {
            printf("%s", buffer);
            size_t len = strlen(buffer);
            if (output && total_bytes + len < output_size) {
                strncpy(output + total_bytes, buffer, output_size - total_bytes);
                total_bytes += len;
            }
        } else {
            break;
        }
    }

    fclose(pipe);
    if (timed_out) {
        kill(pid, SIGTERM);
        usleep(100000);
        kill(pid, SIGKILL);
    }
    int status;
    waitpid(pid, &status, 0);
    bool success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    char msg[256];
    snprintf(msg, sizeof(msg), "命令%s，退出码: %d", success ? "成功" : "失败", WEXITSTATUS(status));
    log_message(success ? "INFO" : "ERROR", msg);
    return success;
}

bool analyze_with_otool(const char *binary_path, int options) {
    char msg[256];
    snprintf(msg, sizeof(msg), "开始使用 otool 分析 %s", binary_path);
    log_message("INFO", msg);
    printf("\n=== 使用 otool 分析 %s ===\n", binary_path);

    bool success = true;
    char output[4096] = {0};

    if (options & 1) {
        char cmd[MAX_CMD];
        snprintf(cmd, MAX_CMD, "otool -L %s", binary_path);
        success &= run_command(cmd, output, sizeof(output));
    }
    if (options & 2) {
        char cmd[MAX_CMD];
        snprintf(cmd, MAX_CMD, "otool -h %s", binary_path);
        success &= run_command(cmd, output, sizeof(output));
    }
    if (options & 4) {
        char cmd[MAX_CMD];
        snprintf(cmd, MAX_CMD, "otool -tV %s | head -n 10", binary_path);
        success &= run_command(cmd, output, sizeof(output));
    }

    snprintf(msg, sizeof(msg), "otool 分析%s，结果%s", success ? "完成" : "失败", strlen(output) > 0 ? "可用" : "不可用");
    log_message(success ? "INFO" : "ERROR", msg);
    return success && strlen(output) > 0;
}

bool debug_with_lldb(const char *binary_path, const char *lldb_script, int pid) {
    char msg[256];
    snprintf(msg, sizeof(msg), "开始使用 LLDB 调试 %s%s", binary_path, pid ? " (PID: " : "");
    log_message("INFO", msg);
    printf("\n=== 使用 LLDB 调试 %s%s ===\n", binary_path, pid ? " (PID: " : "");

    char cmd[MAX_CMD];
    char output[4096] = {0};
    if (pid) {
        snprintf(cmd, MAX_CMD, "lldb -s %s -p %d", lldb_script, pid);
    } else {
        snprintf(cmd, MAX_CMD, "lldb -s %s %s", lldb_script, binary_path);
    }
    bool success = run_command(cmd, output, sizeof(output));

    snprintf(msg, sizeof(msg), "LLDB 调试%s，结果%s", success ? "完成" : "失败", strlen(output) > 0 ? "可用" : "不可用");
    log_message(success ? "INFO" : "ERROR", msg);
    return success && strlen(output) > 0;
}

bool disassemble_with_hopper(const char *binary_path, bool pseudo_code) {
    char msg[256];
    snprintf(msg, sizeof(msg), "开始使用 Hopper 反汇编 %s", binary_path);
    log_message("INFO", msg);
    printf("\n=== 使用 Hopper 反汇编 %s ===\n", binary_path);

    char output_file[] = "hopper_output.txt";
    char cmd[MAX_CMD];
    snprintf(cmd, MAX_CMD, "hopperv4 -e %s -o %s %s", pseudo_code ? "--pseudo-code" : "--asm", output_file, binary_path);
    bool cmd_success = system(cmd) == 0;

    bool file_success = false;
    FILE *file = fopen(output_file, "r");
    if (file) {
        char buffer[1024];
        while (fgets(buffer, sizeof(buffer), file)) {
            printf("%s", buffer);
        }
        fclose(file);
        file_success = true;
    } else {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "无法读取 Hopper 输出文件: %s", strerror(errno));
        log_message("ERROR", err_msg);
    }

    if (file_success) remove(output_file);
    snprintf(msg, sizeof(msg), "Hopper 反汇编%s，结果%s", cmd_success ? "完成" : "失败", file_success ? "可用" : "不可用");
    log_message(cmd_success && file_success ? "INFO" : "ERROR", msg);
    return cmd_success && file_success;
}

int get_user_options() {
    printf("请选择 otool 分析范围（输入编号，多个用空格分隔，留空则全选）：\n");
    printf("1. 依赖库\n2. Mach-O 头部信息\n3. 反汇编文本段\n");
    printf("您的选择（例如 '1 2'）：");
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        log_message("ERROR", "读取 otool 选项失败");
        return 0;
    }
    input[strcspn(input, "\n")] = 0;

    if (strlen(input) == 0) return 7;
    int options = 0;
    char *token = strtok(input, " ");
    while (token) {
        int choice = atoi(token);
        if (choice >= 1 && choice <= 3) options |= (1 << (choice - 1));
        token = strtok(NULL, " ");
    }
    return options;
}

void get_lldb_commands(char *script_path, int *pid) {
    log_message("INFO", "获取 LLDB 调试选项");
    printf("\n请选择 LLDB 调试选项（输入编号，多个用空格分隔）：\n");
    printf("1. 在 main 设置断点并运行\n2. 检查整数溢出\n3. 检查浮点溢出\n4. 检查指针修改\n5. 进程注入\n6. 汇编调试（stepi）\n7. 覆盖返回地址\n8. 查看栈布局\n9. 跟踪函数调用\n10. 跟踪动态内存\n11. 修改动态值\n12. 绕过限制\n");
    printf("您的选择（例如 '1 2'）：");
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        log_message("ERROR", "读取 LLDB 选项失败");
        return;
    }
    input[strcspn(input, "\n")] = 0;

    FILE *script = fopen(script_path, "w");
    if (!script) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "无法创建 LLDB 脚本文件: %s", strerror(errno));
        log_message("ERROR", err_msg);
        printf("\n错误：无法创建 LLDB 脚本文件\n");
        return;
    }

    char *token = strtok(input, " ");
    while (token && !interrupted) {
        int choice = atoi(token);
        switch (choice) {
            case 1: fprintf(script, "breakpoint set --name main\nrun\nthread backtrace\ncontinue\n"); break;
            case 2: fprintf(script, "breakpoint set --name add\nrun\nprint a\nprint b\nprint (int)(a + b)\ncontinue\n"); break;
            case 3: fprintf(script, "breakpoint set --name float_overflow\nrun\nprint x\nprint (double)(x * 1e308)\ncontinue\n"); break;
            case 4: fprintf(script, "breakpoint set --name modify_pointer\nrun\nprint *ptr\nnext\nprint *ptr\ncontinue\n"); break;
            case 5: {
                printf("请输入目标进程的 PID（留空则启动新进程）：");
                char pid_input[32];
                if (!fgets(pid_input, sizeof(pid_input), stdin)) break;
                pid_input[strcspn(pid_input, "\n")] = 0;
                if (strlen(pid_input) > 0) {
                    *pid = atoi(pid_input);
                    fprintf(script, "process attach --pid %d\nexpression -- int value = 100\nthread backtrace\ncontinue\n", *pid);
                } else {
                    fprintf(script, "run\nexpression -- int value = 100\nthread backtrace\ncontinue\n");
                }
                break;
            }
            case 6: {
                printf("请输入要调试的函数名（默认 main）：");
                char func[64];
                if (!fgets(func, sizeof(func), stdin)) break;
                func[strcspn(func, "\n")] = 0;
                if (strlen(func) == 0) strcpy(func, "main");

                printf("请输入 stepi 执行步数（默认 5）：");
                char steps[16];
                if (!fgets(steps, sizeof(steps), stdin)) break;
                steps[strcspn(steps, "\n")] = 0;
                int step_count = strlen(steps) ? atoi(steps) : 5;

                fprintf(script, "breakpoint set --name %s\nrun\ndisassemble --count 10\nregister read\n", func);
                for (int i = 0; i < step_count; i++) fprintf(script, "stepi\n");
                fprintf(script, "register read\ncontinue\n");
                break;
            }
            case 7: {
                printf("请输入目标函数名（默认 main）：");
                char func[64];
                if (!fgets(func, sizeof(func), stdin)) break;
                func[strcspn(func, "\n")] = 0;
                if (strlen(func) == 0) strcpy(func, "main");

                printf("请输入新的返回地址（十六进制，例如 0x100000f70）：");
                char new_addr[32];
                if (!fgets(new_addr, sizeof(new_addr), stdin)) break;
                new_addr[strcspn(new_addr, "\n")] = 0;

                fprintf(script, "breakpoint set --name %s\nrun\n", func);
                fprintf(script, "register read lr\n");
                fprintf(script, "register write lr %s\n", new_addr);
                fprintf(script, "thread backtrace\ncontinue\n");
                break;
            }
            case 8: {
                printf("请输入目标函数名（默认 main）：");
                char func[64];
                if (!fgets(func, sizeof(func), stdin)) break;
                func[strcspn(func, "\n")] = 0;
                if (strlen(func) == 0) strcpy(func, "main");

                printf("请输入要读取的栈字节数（默认 32）：");
                char bytes[16];
                if (!fgets(bytes, sizeof(bytes), stdin)) break;
                bytes[strcspn(bytes, "\n")] = 0;
                int byte_count = strlen(bytes) ? atoi(bytes) : 32;

                fprintf(script, "breakpoint set --name %s\nrun\n", func);
                fprintf(script, "frame info\n");
                fprintf(script, "memory read --size 8 --count %d $sp\n", byte_count / 8);
                fprintf(script, "thread backtrace\ncontinue\n");
                break;
            }
            case 9: {
                printf("请输入要跟踪的函数名（默认 main）：");
                char func[64];
                if (!fgets(func, sizeof(func), stdin)) break;
                func[strcspn(func, "\n")] = 0;
                if (strlen(func) == 0) strcpy(func, "main");

                printf("请输入跟踪次数上限（默认 10）：");
                char count[16];
                if (!fgets(count, sizeof(count), stdin)) break;
                count[strcspn(count, "\n")] = 0;
                int trace_count = strlen(count) ? atoi(count) : 10;

                fprintf(script, "breakpoint set --name %s\n", func);
                fprintf(script, "breakpoint command add\n");
                fprintf(script, "thread backtrace\n");
                fprintf(script, "continue\n");
                fprintf(script, "DONE\n");
                fprintf(script, "breakpoint modify --auto-continue 1 --one-shot 0 --hit-count %d\n", trace_count);
                fprintf(script, "run\n");
                break;
            }
            case 10: {
                printf("请输入跟踪动态内存的次数上限（默认 10）：");
                char count[16];
                if (!fgets(count, sizeof(count), stdin)) break;
                count[strcspn(count, "\n")] = 0;
                int trace_count = strlen(count) ? atoi(count) : 10;

                fprintf(script, "breakpoint set --name malloc\n");
                fprintf(script, "breakpoint command add 1\n");
                fprintf(script, "printf \"malloc: size = %%lu, address = %%p\\n\", $x0, $x0\n");
                fprintf(script, "thread return\n");
                fprintf(script, "printf \"malloc returned: %%p\\n\", $x0\n");
                fprintf(script, "continue\n");
                fprintf(script, "DONE\n");
                fprintf(script, "breakpoint modify 1 --auto-continue 1 --hit-count %d\n", trace_count);
                fprintf(script, "breakpoint set --name free\n");
                fprintf(script, "breakpoint command add 2\n");
                fprintf(script, "printf \"free: address = %%p\\n\", $x0\n");
                fprintf(script, "continue\n");
                fprintf(script, "DONE\n");
                fprintf(script, "breakpoint modify 2 --auto-continue 1 --hit-count %d\n", trace_count);
                fprintf(script, "run\n");
                break;
            }
            case 11: {
                printf("请输入目标函数名（默认 main）：");
                char func[64];
                if (!fgets(func, sizeof(func), stdin)) break;
                func[strcspn(func, "\n")] = 0;
                if (strlen(func) == 0) strcpy(func, "main");

                printf("请输入要修改的内存地址（十六进制，例如 0x100000f70）：");
                char addr[32];
                if (!fgets(addr, sizeof(addr), stdin)) break;
                addr[strcspn(addr, "\n")] = 0;

                printf("请输入新值（整数，例如 42）：");
                char value[32];
                if (!fgets(value, sizeof(value), stdin)) break;
                value[strcspn(value, "\n")] = 0;

                fprintf(script, "breakpoint set --name %s\n", func);
                fprintf(script, "run\n");
                fprintf(script, "memory read --size 4 --count 1 %s\n", addr);
                fprintf(script, "memory write %s %s\n", addr, value);
                fprintf(script, "memory read --size 4 --count 1 %s\n", addr);
                fprintf(script, "thread backtrace\n");
                fprintf(script, "continue\n");
                break;
            }
            case 12: {
                printf("请输入目标函数名（默认 main）：");
                char func[64];
                if (!fgets(func, sizeof(func), stdin)) break;
                func[strcspn(func, "\n")] = 0;
                if (strlen(func) == 0) strcpy(func, "main");

                printf("请输入绕过类型（1: 返回真, 2: 返回假, 3: 跳过下一指令）：");
                char bypass_type[16];
                if (!fgets(bypass_type, sizeof(bypass_type), stdin)) break;
                bypass_type[strcspn(bypass_type, "\n")] = 0;
                int type = atoi(bypass_type);

                fprintf(script, "breakpoint set --name %s\n", func);
                fprintf(script, "run\n");
                fprintf(script, "register read\n");
                switch (type) {
                    case 1: fprintf(script, "register write x0 1\n"); log_message("INFO", "绕过限制：将函数返回设置为真"); break;
                    case 2: fprintf(script, "register write x0 0\n"); log_message("INFO", "绕过限制：将函数返回设置为假"); break;
                    case 3: fprintf(script, "stepi\n"); log_message("INFO", "绕过限制：跳过下一条指令"); break;
                    default: fprintf(script, "register write x0 1\n"); log_message("WARNING", "无效绕过类型，默认设置为返回真");
                }
                fprintf(script, "register read\n");
                fprintf(script, "thread backtrace\n");
                fprintf(script, "continue\n");
                break;
            }
            default: printf("警告：无效选项 %d，已忽略\n", choice);
        }
        token = strtok(NULL, " ");
    }
    fprintf(script, "exit\n");
    fclose(script);
    log_message("INFO", "LLDB 脚本生成完成");
}

bool get_analysis_choice(int *otool_options, bool *use_lldb, bool *use_hopper, char *lldb_script, int *pid, bool *hopper_pseudo) {
    log_message("INFO", "获取分析工具选择");
    printf("\n请选择分析工具（输入编号，多个用空格分隔）：\n");
    printf("1. otool 分析\n2. LLDB 调试\n3. Hopper 反汇编\n");
    printf("您的选择（例如 '1 2'）：");
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        log_message("ERROR", "读取分析工具选择失败");
        return false;
    }
    input[strcspn(input, "\n")] = 0;

    *otool_options = 0;
    *use_lldb = false;
    *use_hopper = false;

    char *token = strtok(input, " ");
    while (token) {
        int choice = atoi(token);
        switch (choice) {
            case 1: *otool_options = get_user_options(); break;
            case 2: *use_lldb = true; get_lldb_commands(lldb_script, pid); break;
            case 3: {
                *use_hopper = true;
                printf("是否生成伪代码？(y/n): ");
                char pseudo[4];
                if (!fgets(pseudo, sizeof(pseudo), stdin)) break;
                *hopper_pseudo = (pseudo[0] == 'y' || pseudo[0] == 'Y');
                break;
            }
            default: printf("警告：无效选项 %d，已忽略\n", choice);
        }
        token = strtok(NULL, " ");
    }
    return *otool_options || *use_lldb || *use_hopper;
}

bool modify_settings(int *otool_options, char *lldb_script, bool *use_lldb, bool *use_hopper, int *pid, bool *hopper_pseudo) {
    log_message("INFO", "进入修改设置");
    printf("\n=== 修改设置 ===\n");
    printf("当前 otool 分析范围：%s%s%s\n",
           (*otool_options & 1) ? "依赖库 " : "",
           (*otool_options & 2) ? "头部信息 " : "",
           (*otool_options & 4) ? "反汇编" : "");
    printf("当前 LLDB 使用：%s（脚本：%s）\n", *use_lldb ? "是" : "否", lldb_script);
    printf("当前 Hopper 使用：%s（%s）\n", *use_hopper ? "是" : "否", *hopper_pseudo ? "伪代码" : "汇编");

    printf("是否修改设置？(y/n): ");
    char choice[4];
    if (!fgets(choice, sizeof(choice), stdin)) {
        log_message("ERROR", "读取修改设置选项失败");
        return false;
    }
    if (choice[0] != 'y' && choice[0] != 'Y') return false;

    return get_analysis_choice(otool_options, use_lldb, use_hopper, lldb_script, pid, hopper_pseudo);
}

int get_launch_mode() {
    printf("\n请选择启动模式（输入编号）：\n");
    printf("1. 顺序模式（依次运行所有工具）\n");
    printf("2. 并行模式（同时运行所有工具）\n");
    printf("3. 单工具模式（仅运行指定工具）\n");
    printf("您的选择（默认 2）：");
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        log_message("ERROR", "读取启动模式失败");
        return 2; // 默认并行模式
    }
    input[strcspn(input, "\n")] = 0;
    int mode = strlen(input) ? atoi(input) : 2;
    if (mode < 1 || mode > 3) {
        log_message("WARNING", "无效启动模式，默认使用并行模式");
        return 2;
    }
    return mode;
}

void run_sequential(const char *binary_path, int otool_options, const char *lldb_script, int pid, bool hopper_pseudo) {
    bool otool_result = otool_options ? analyze_with_otool(binary_path, otool_options) : true;
    bool lldb_result = (access(lldb_script, F_OK) == 0) ? debug_with_lldb(binary_path, lldb_script, pid) : true;
    bool hopper_result = hopper_pseudo ? disassemble_with_hopper(binary_path, hopper_pseudo) : true;
    printf("\n=== 顺序模式结果 ===\n");
    printf("otool: %s\n", otool_result ? "成功，结果可用" : "失败或结果不可用");
    printf("LLDB: %s\n", lldb_result ? "成功，结果可用" : "失败或结果不可用");
    printf("Hopper: %s\n", hopper_result ? "成功，结果可用" : "失败或结果不可用");
}

void *otool_wrapper(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    args->otool_result = analyze_with_otool(args->binary_path, args->otool_options);
    return NULL;
}

void *lldb_wrapper(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    args->lldb_result = debug_with_lldb(args->binary_path, args->lldb_script, args->pid);
    return NULL;
}

void *hopper_wrapper(void *arg) {
    ThreadArgs *args = (ThreadArgs *)arg;
    args->hopper_result = disassemble_with_hopper(args->binary_path, args->hopper_pseudo);
    return NULL;
}

void run_parallel(const char *binary_path, int otool_options, const char *lldb_script, int pid, bool hopper_pseudo) {
    pthread_t threads[MAX_THREADS] = {0};
    int thread_count = 0;
    ThreadArgs args = {binary_path, otool_options, lldb_script, pid, hopper_pseudo, false, false, false};
    int rc;

    if (otool_options) {
        rc = pthread_create(&threads[thread_count++], NULL, otool_wrapper, &args);
        if (rc) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "创建 otool 线程失败: %s", strerror(rc));
            log_message("ERROR", err_msg);
        }
    }
    if (access(lldb_script, F_OK) == 0) {
        rc = pthread_create(&threads[thread_count++], NULL, lldb_wrapper, &args);
        if (rc) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "创建 LLDB 线程失败: %s", strerror(rc));
            log_message("ERROR", err_msg);
        }
    }
    if (hopper_pseudo) {
        rc = pthread_create(&threads[thread_count++], NULL, hopper_wrapper, &args);
        if (rc) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "创建 Hopper 线程失败: %s", strerror(rc));
            log_message("ERROR", err_msg);
        }
    }

    for (int i = 0; i < thread_count; i++) {
        if (threads[i]) {
            rc = pthread_join(threads[i], NULL);
            if (rc) {
                char err_msg[256];
                snprintf(err_msg, sizeof(err_msg), "等待线程 %d 失败: %s", i, strerror(rc));
                log_message("ERROR", err_msg);
            }
        }
    }

    printf("\n=== 并行模式结果 ===\n");
    printf("otool: %s\n", args.otool_result ? "成功，结果可用" : "失败或结果不可用");
    printf("LLDB: %s\n", args.lldb_result ? "成功，结果可用" : "失败或结果不可用");
    printf("Hopper: %s\n", args.hopper_result ? "成功，结果可用" : "失败或结果不可用");
}

void run_single_tool(const char *binary_path, int otool_options, const char *lldb_script, int pid, bool hopper_pseudo) {
    printf("\n请选择要运行的工具（输入编号）：\n");
    printf("1. otool\n2. LLDB\n3. Hopper\n");
    char input[256];
    if (!fgets(input, sizeof(input), stdin)) {
        log_message("ERROR", "读取单工具选择失败");
        return;
    }
    int tool = atoi(input);
    bool result = false;

    switch (tool) {
        case 1: if (otool_options) result = analyze_with_otool(binary_path, otool_options); break;
        case 2: if (access(lldb_script, F_OK) == 0) result = debug_with_lldb(binary_path, lldb_script, pid); break;
        case 3: if (hopper_pseudo) result = disassemble_with_hopper(binary_path, hopper_pseudo); break;
        default: printf("无效选择！\n"); return;
    }

    printf("\n=== 单工具模式结果 ===\n");
    printf("工具 %d: %s\n", tool, result ? "成功，结果可用" : "失败或结果不可用");
}

int main() {
    signal(SIGINT, signal_handler);
    log_message("INFO", "程序启动");

    char input_path[MAX_PATH];
    printf("请输入二进制文件或 C 文件路径: ");
    if (!fgets(input_path, sizeof(input_path), stdin)) {
        log_message("ERROR", "读取输入路径失败");
        return 1;
    }
    input_path[strcspn(input_path, "\n")] = 0;
    log_message("INFO", input_path);

    char binary_path[MAX_PATH];
    bool is_c_file = strstr(input_path, ".c") != NULL;
    if (is_c_file) {
        printf("\n检测到 C 文件：%s，正在编译...\n", input_path);
        strcpy(binary_path, "temp_binary");
        if (!compile_c_file(input_path, binary_path)) return 1;
    } else {
        strcpy(binary_path, input_path);
    }

    if (access(binary_path, F_OK) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "目标文件不存在: %s", binary_path);
        log_message("ERROR", err_msg);
        printf("错误：文件 %s 不存在！\n", binary_path);
        return 1;
    }
    if (access(binary_path, X_OK) != 0) {
        char warn_msg[256];
        snprintf(warn_msg, sizeof(warn_msg), "目标文件可能不是可执行文件: %s", binary_path);
        log_message("WARNING", warn_msg);
        printf("警告：%s 可能不是可执行文件！\n", binary_path);
    }

    int otool_options = 0;
    bool use_lldb = false, use_hopper = false, hopper_pseudo = false;
    char lldb_script[] = "lldb_script.txt";
    int pid = 0;

    if (!get_analysis_choice(&otool_options, &use_lldb, &use_hopper, lldb_script, &pid, &hopper_pseudo)) {
        log_message("WARNING", "未选择任何分析工具");
        printf("未选择任何工具，程序退出。\n");
        return 0;
    }

    int iteration = 0;
    while (iteration < MAX_ITERATIONS && !interrupted) {
        char msg[64];
        snprintf(msg, sizeof(msg), "开始第 %d 次分析", iteration + 1);
        log_message("INFO", msg);
        printf("\n第 %d 次分析（最大 %d 次）\n", iteration + 1, MAX_ITERATIONS);

        int mode = get_launch_mode();
        switch (mode) {
            case 1: run_sequential(binary_path, otool_options, lldb_script, pid, hopper_pseudo); break;
            case 2: run_parallel(binary_path, otool_options, lldb_script, pid, hopper_pseudo); break;
            case 3: run_single_tool(binary_path, otool_options, lldb_script, pid, hopper_pseudo); break;
        }

        if (!modify_settings(&otool_options, lldb_script, &use_lldb, &use_hopper, &pid, &hopper_pseudo)) {
            printf("\n是否退出程序？(y/n): ");
            char choice[4];
            if (!fgets(choice, sizeof(choice), stdin)) {
                log_message("ERROR", "读取退出选择失败");
                break;
            }
            if (choice[0] == 'y' || choice[0] == 'Y') {
                log_message("INFO", "用户选择退出程序");
                break;
            }
            log_message("INFO", "重新运行当前设置");
            printf("\n重新运行当前设置...\n");
        }
        iteration++;
    }

    if (iteration >= MAX_ITERATIONS) {
        log_message("INFO", "达到最大循环次数，程序退出");
        printf("\n达到最大循环次数 %d，程序自动退出\n", MAX_ITERATIONS);
    }

    if (is_c_file && access(binary_path, F_OK) == 0) {
        if (remove(binary_path) != 0) {
            char err_msg[256];
            snprintf(err_msg, sizeof(err_msg), "清理临时文件失败: %s", strerror(errno));
            log_message("ERROR", err_msg);
        } else {
            log_message("INFO", "清理临时二进制文件");
            printf("\n已清理临时二进制文件：%s\n", binary_path);
        }
    }
    if (access(lldb_script, F_OK) == 0 && remove(lldb_script) != 0) {
        char err_msg[256];
        snprintf(err_msg, sizeof(err_msg), "清理 LLDB 脚本文件失败: %s", strerror(errno));
        log_message("ERROR", err_msg);
    }
    log_message("INFO", "程序结束");
    return 0;
}
