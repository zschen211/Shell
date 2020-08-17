/**
 * Shell
 * CS 241 - Spring 2020
 */
#include "format.h"
#include "shell.h"
#include "vector.h"
#include "sstring.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <time.h>

typedef struct process {
    char *command;
    pid_t pid;
} process;

// prompt
void prompt() {
    char *buffer = get_current_dir_name();
    pid_t pid = getpid();
    print_prompt(buffer, pid);    
    free(buffer);
}

// read command
vector *read_cmd(char *line) {
    sstring *command = cstr_to_sstring(line);
    vector *cmd_word = sstring_split(command, ' ');
    if (vector_size(cmd_word) == 1 && strcmp(vector_get(cmd_word, 0), "") == 0) {
        print_usage();
    }
    sstring_destroy(command);
    return cmd_word;
}

// external command
void external(char *line, char **arg, vector *pid_ls, int background) {
    fflush(stdout);
    fflush(stdin);
    pid_t pid = fork();
    if (pid < 0) {
        print_fork_failed();
        exit(1);
    } else if (pid > 0) {
        vector_push_back(pid_ls, &pid);
        print_command_executed(pid);
        int status;
        pid_t child;
        if (background) {
            child = waitpid(pid, &status, WNOHANG);
        } else {
            child = waitpid(pid, &status, 0);
        }
        if (child == -1) {
            print_wait_failed();
        }
        if (WIFEXITED(status)) {
            if(WEXITSTATUS(status)) {
                print_exec_failed(line);
            }
        }
        // kill(child, SIGKILL);
    } else {
        int s = setpgid(0, 0);
        if (s == -1) {
            print_setpgid_failed();
        }
        execvp(arg[0], arg);
        exit(1);
    }
}

// built-in: cd
void cd(char *line, vector *cmd) {
    // handle invalid use
    if (vector_size(cmd) == 1) {
        print_no_directory("");
    } else if (vector_size(cmd) > 2) {
        print_invalid_command(line);
    } else {
        char *dir = vector_get(cmd, 1);
        DIR *directory = opendir(dir);
        if (directory == NULL) {
            print_no_directory(dir);
        } else {
            chdir(dir);
        }
        closedir(directory);
    }
}

// built_in: !history
void cmd_hist(char *line, vector *cmd, vector *hist) {
    if (vector_size(cmd) > 1 || vector_size(hist) == 0) {
        print_invalid_command(line);
        return;
    }
    for (size_t i = 0; i < vector_size(hist); i++) {
        print_history_line(i, vector_get(hist, i));
    }
}

// built_in: #<n>
void nth_cmd(char *line, vector *cmd, vector *hist, vector *pid_ls) {
    if (vector_size(cmd) > 1) {
        print_invalid_command(line);
        return;
    }
    char *ptr = line + 1;
    int num = atoi(ptr);
    if (num >= (int)vector_size(hist)) {
        print_invalid_index();
        return;
    } else {
        char *new_line = vector_get(hist, num);
        vector *new_cmd = read_cmd(new_line);
        vector_push_back(hist, new_line);
        if (strcmp(vector_get(new_cmd, 0), "cd") == 0) {
            cd(new_line, new_cmd);
        } else {
            // malloc for string array to pass in argument for external
            size_t arg_size = vector_size(new_cmd) + 1;
            char **arg = malloc(arg_size*sizeof(char *));
            for (size_t i = 0; i < arg_size - 1; i++) {
                arg[i] = vector_get(new_cmd, i);
            }
            arg[arg_size - 1] = NULL;
            // execute external
            external(new_line, arg, pid_ls, 0);
            free(arg);   
        }
        vector_destroy(new_cmd);
    }
}

// built-in: !<prefix>
void prefix(char *line, vector *hist, vector *pid_ls) {
    size_t idx = 0;
    for (int i = (int)vector_size(hist) - 1; i >= 0; i--) {
        char *hist_line = vector_get(hist, i);
        if (strlen(line) - 1 > strlen(hist_line)) {
            continue;
        }
        int same = 1;
        for (size_t j = 1; j < strlen(line); j++) {
            if (line[j] != hist_line[j-1]) {
                same = 0;
            }
        }
        if (same) {
            idx = i;
            char *new_line = vector_get(hist, idx);
            vector *new_cmd = read_cmd(new_line);
            vector_push_back(hist, new_line);
            if (strcmp(vector_get(new_cmd, 0), "cd") == 0) {
                cd(new_line, new_cmd);
            } else {
                // malloc for string array to pass in argument for external
                size_t arg_size = vector_size(new_cmd) + 1;
                char **arg = malloc(arg_size*sizeof(char *));
                for (size_t i = 0; i < arg_size - 1; i++) {
                    arg[i] = vector_get(new_cmd, i);
                }
                arg[arg_size - 1] = NULL;
                // execute external
                external(new_line, arg, pid_ls, 0);
                free(arg);  
            }
            vector_destroy(new_cmd);
            return;
        }
    }
    print_no_history_match();
}

// output and append redirection
void output(char *line, char **argv, vector *pid_ls) {
    // fflush(stdout);
    // fflush(stdin);
    pid_t pid = fork();
    if (pid < 0) {
        print_fork_failed();
        exit(1);
    } else if (pid > 0) {
        vector_push_back(pid_ls, &pid);
        int status;
        pid_t child;
        child = waitpid(pid, &status, 0);
        if (child == -1) {
            print_wait_failed();
        }
        if (WIFEXITED(status)) {
            if(WEXITSTATUS(status)) {
                print_exec_failed(line);
            }
        }
        // kill(child, SIGKILL);
    } else {
        int s = setpgid(0, 0);
        if (s == -1) {
            print_setpgid_failed();
        }
        execvp(argv[0], argv);
        exit(1);
    }
}

// redirection operation
void redirection(char *line, vector *cmd, vector *pid_ls) {
    // update hist
    // vector_push_back(hist, line);
    // parsing
    char *cmd_line = calloc(strlen(line), 1);
    char **argv = calloc(vector_size(cmd) - 1, sizeof(char *));
    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == '>' || line[i] == '<') {
            break;
        }
        cmd_line[i] = line[i];
    }
    for (size_t i = 0; i < vector_size(cmd) - 2; i++) {
        argv[i] = vector_get(cmd, i);
    }
    // open file
    char *path = get_current_dir_name();
    char *path_txt = calloc(strlen(path) + strlen(vector_get(cmd, vector_size(cmd) - 1)) + 2, 1);
    strcat(path_txt, path);
    strcat(path_txt, "/");
    strcat(path_txt, vector_get(cmd, vector_size(cmd) - 1));
    int fd = 0;
    // redir operation
    if (strcmp(vector_get(cmd, vector_size(cmd) - 2), ">") == 0) {
        fd = open(path_txt, O_WRONLY | O_TRUNC);
        if (fd == -1) {
            print_redirection_file_error();
            return;
        }
        int savestdout = dup(1);
        dup2(fd, 1);
        output(cmd_line, argv, pid_ls);
        dup2(savestdout, 1);
        print_command_executed(*(pid_t *)vector_get(pid_ls, vector_size(pid_ls) - 1));
        close(fd);
        close(savestdout);
    } else if (strcmp(vector_get(cmd, vector_size(cmd) - 2), ">>") == 0) {
        fd = open(path_txt, O_CREAT | O_WRONLY | O_APPEND);
        if (fd == -1) {
            print_redirection_file_error();
            return;
        }
        int savestdout = dup(1);
        dup2(fd, 1);
        output(cmd_line, argv, pid_ls);
        dup2(savestdout, 1);
        print_command_executed(*(pid_t *)vector_get(pid_ls, vector_size(pid_ls) - 1));
        close(fd);
        close(savestdout);
    } else {
        fd = open(path_txt, O_RDONLY);
        if (fd == -1) {
            print_redirection_file_error();
            return;
        }
        int savestdin = dup(0);
        dup2(fd, 0);
        external(cmd_line, argv, pid_ls, 0);
        dup2(savestdin, 0);
        close(fd);
        close(savestdin);
    }
    // cleanup heap
    free(cmd_line);
    free(argv);
    free(path);
    free(path_txt);
}

// ps
void ps() {
    print_process_info_header();
    // get all pids in proc dir 
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        return;
    }
    vector *pid_ls = int_vector_create();
    pid_t parent = getpid();
    struct dirent *d;
    while ((d = readdir(proc)) != NULL) {
        char *d_name = d->d_name;
        int d_num = atoi(d_name);
        if (d_num != 0) {
            vector_push_back(pid_ls, &d_num);
        }
    }
    closedir(proc);
    // get all child pids
    for (size_t i = 0; i < vector_size(pid_ls); i++) {
        // get all stats of current process
        char *f_name = calloc(50, 1);
        sprintf(f_name, "/proc/%d/stat", *(int *)vector_get(pid_ls, i));
        FILE *f = fopen(f_name, "r");
        char *line = NULL;
        size_t n = 0;
        ssize_t l_size = getline(&line, &n, f);
        if (l_size != -1) {
            line[strlen(line)] = '\0';
        }
        sstring *ss_line = cstr_to_sstring(line);
        vector *stat = sstring_split(ss_line, ' ');
        // if is child process, print info
        if (atoi((char *)vector_get(stat, 0)) == (int)parent || atoi((char *)vector_get(stat, 3)) == (int)parent) {
            // initialize struct
            process_info *temp = calloc(1, sizeof(process_info));
            temp->start_str = calloc(100, 1);
            temp->time_str = calloc(100, 1);
            temp->command = calloc(500, 1);
            // assign values
            temp->pid = atoi((char *)vector_get(stat, 0));
            temp->nthreads = atoi((char *)vector_get(stat, 19));
            temp->vsize = atoi((char *)vector_get(stat, 22))/1024;
            temp->state = *(char *)vector_get(stat, 2);
            // get start time
            time_t raw;
            struct tm *info;
            time(&raw);
            info = localtime(&raw);
            time_struct_to_string(temp->start_str, 6, info);
            // get exec time
            int time_sc = (atoi((char *)vector_get(stat, 13)) + atoi((char *)vector_get(stat, 14)))/sysconf(_SC_CLK_TCK);
            sprintf(temp->time_str, "%d:%d%d", time_sc/60, (time_sc%60)/10, (time_sc%60)%10);
            execution_time_to_string(temp->time_str, 5, time_sc/60, time_sc%60);
            // open cmdline file to parse sprintf;
            char *cmdline = calloc(50, 1);
            sprintf(cmdline, "/proc/%d/cmdline", *(int *)vector_get(pid_ls, i));
            FILE *tmp_f = fopen(cmdline, "r");
            int idx = 0;
            int c = 0;
            while((c = getc(tmp_f)) != EOF) {
                if (c == 0) {
                    temp->command[idx] = ' ';
                } else {
                    temp->command[idx] = (char)c;
                }
                idx++;
            }
            temp->command[strlen(temp->command) - 1] = '\0';
            fclose(tmp_f);
            print_process_info(temp);
            // cleanup memory
            free(cmdline);
            free(temp->command);
            free(temp->start_str);
            free(temp->time_str);
            free(temp);
        }  
        fclose(f);
        free(line);
        free(f_name);
        vector_destroy(stat);
        sstring_destroy(ss_line);
    }
    vector_destroy(pid_ls);
}

// kill signal
void kill_command(int pid) {
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        return;
    }
    vector *pid_ls = int_vector_create();
    struct dirent *d;
    while ((d = readdir(proc)) != NULL) {
        char *d_name = d->d_name;
        int d_num = atoi(d_name);
        if (d_num != 0) {
            vector_push_back(pid_ls, &d_num);
        }
    }
    closedir(proc);
    int exist = 0;
    for (size_t i = 0; i < vector_size(pid_ls); i++) {
        if (*(int *)vector_get(pid_ls, i) == pid) {
            exist = 1;
            break;
        }
    }
    // print error message
    if (!exist || !pid) {
        print_no_process_found(pid);
        vector_destroy(pid_ls);
        return;
    }
    // kill process and print
    kill(pid, SIGTERM);
    char *cmdline = calloc(50, 1);
    sprintf(cmdline, "/proc/%d/cmdline", pid);
    FILE *tmp_f = fopen(cmdline, "r");
    char *cmd = calloc(500, 1);
    int idx = 0;
    int c = 0;
    while((c = getc(tmp_f)) != EOF) {
        if (c == 0) {
            cmd[idx] = ' ';
        } else {
            cmd[idx] = (char)c;
        }
        idx++;
    }
    cmd[strlen(cmd) - 1] = '\0';
    fclose(tmp_f);
    print_killed_process(pid, cmd);
    // clean up heap
    free(cmdline);
    free(cmd);
    vector_destroy(pid_ls);
}

// stop signal
void stop_command(int pid) {
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        return;
    }
    vector *pid_ls = int_vector_create();
    struct dirent *d;
    while ((d = readdir(proc)) != NULL) {
        char *d_name = d->d_name;
        int d_num = atoi(d_name);
        if (d_num != 0) {
            vector_push_back(pid_ls, &d_num);
        }
    }
    closedir(proc);
    int exist = 0;
    for (size_t i = 0; i < vector_size(pid_ls); i++) {
        if (*(int *)vector_get(pid_ls, i) == pid) {
            exist = 1;
            break;
        }
    }
    // print error message
    if (!exist || !pid) {
        print_no_process_found(pid);
        vector_destroy(pid_ls);
        return;
    }
    // stop process and print
    kill(pid, SIGSTOP);
    char *cmdline = calloc(50, 1);
    sprintf(cmdline, "/proc/%d/cmdline", pid);
    FILE *tmp_f = fopen(cmdline, "r");
    char *cmd = calloc(500, 1);
    int idx = 0;
    int c = 0;
    while((c = getc(tmp_f)) != EOF) {
        if (c == 0) {
            cmd[idx] = ' ';
        } else {
            cmd[idx] = (char)c;
        }
        idx++;
    }
    cmd[strlen(cmd) - 1] = '\0';
    fclose(tmp_f);
    print_stopped_process(pid, cmd);
    // clean up heap
    free(cmdline);
    free(cmd);
    vector_destroy(pid_ls);
}

// cont signal
void cont_command(int pid) {
    DIR *proc = opendir("/proc");
    if (proc == NULL) {
        return;
    }
    vector *pid_ls = int_vector_create();
    struct dirent *d;
    while ((d = readdir(proc)) != NULL) {
        char *d_name = d->d_name;
        int d_num = atoi(d_name);
        if (d_num != 0) {
            vector_push_back(pid_ls, &d_num);
        }
    }
    closedir(proc);
    int exist = 0;
    for (size_t i = 0; i < vector_size(pid_ls); i++) {
        if (*(int *)vector_get(pid_ls, i) == pid) {
            exist = 1;
            break;
        }
    }
    // print error message
    if (!exist || !pid) {
        print_no_process_found(pid);
        vector_destroy(pid_ls);
        return;
    }
    // stop process and print
    kill(pid, SIGCONT);
    char *cmdline = calloc(50, 1);
    sprintf(cmdline, "/proc/%d/cmdline", pid);
    FILE *tmp_f = fopen(cmdline, "r");
    char *cmd = calloc(500, 1);
    int idx = 0;
    int c = 0;
    while((c = getc(tmp_f)) != EOF) {
        if (c == 0) {
            cmd[idx] = ' ';
        } else {
            cmd[idx] = (char)c;
        }
        idx++;
    }
    cmd[strlen(cmd) - 1] = '\0';
    fclose(tmp_f);
    print_continued_process(pid, cmd);
    // clean up heap
    free(cmdline);
    free(cmd);
    vector_destroy(pid_ls);
}

// execute command
void exe_cmd(char *line, vector *cmd, vector *hist, vector *pid_ls) {
    // redirection
    if (vector_size(cmd) >= 3) {
        if (strcmp(vector_get(cmd, vector_size(cmd) - 2), ">") == 0 || 
            strcmp(vector_get(cmd, vector_size(cmd) - 2), ">>") == 0 || 
            strcmp(vector_get(cmd, vector_size(cmd) - 2), "<") == 0) {
                vector_push_back(hist, line);
                redirection(line, cmd, pid_ls);
                return;
        }
    }
    // check which command to execute
    if (strcmp(vector_get(cmd, 0), "cd") == 0) {
        vector_push_back(hist, line);
        cd(line, cmd);
    } else if (strcmp(vector_get(cmd, 0), "!history") == 0) {
        cmd_hist(line, cmd, hist);
    } else if (line[0] == '#') {
        nth_cmd(line, cmd, hist, pid_ls);
    } else if (line[0] == '!') {
        prefix(line, hist, pid_ls);
    } else if (line && strcmp(line, "ps") == 0) {
        vector_push_back(hist, line);
        ps();
    } else if (strcmp(vector_get(cmd, 0), "kill") == 0) {
        vector_push_back(hist, line);
        kill_command(atoi(vector_get(cmd, 1)));
    } else if (strcmp(vector_get(cmd, 0), "stop") == 0) {
        vector_push_back(hist, line);
        stop_command(atoi(vector_get(cmd, 1)));
    } else if (strcmp(vector_get(cmd, 0), "cont") == 0) {
        vector_push_back(hist, line);
        cont_command(atoi(vector_get(cmd, 1)));
    } else {
        if (vector_size(cmd) > 0) {
            // malloc for string array to pass in argument for external
            size_t arg_size = vector_size(cmd) + 1;
            // execute external
            if (line[strlen(line) - 1] == '&') {
                // running in background process
                char *new_line = calloc(strlen(line) - 1, 1);
                for (size_t i = 0; i < strlen(line) - 2; i++) {
                    new_line[i] = line[i];
                }
                char **new_arg = malloc((arg_size - 1)*sizeof(char *));
                for (size_t i = 0; i < arg_size - 2; i++) {
                    new_arg[i] = vector_get(cmd, i);
                }
                new_arg[arg_size - 2] = NULL;
                external(new_line, new_arg, pid_ls, 1);
                vector_push_back(hist, new_line);
                free(new_arg);
                free(new_line);
            } else {
                // running in foreground
                char **arg = malloc(arg_size*sizeof(char *));
                for (size_t i = 0; i < arg_size - 1; i++) {
                    arg[i] = vector_get(cmd, i);
                }
                arg[arg_size - 1] = NULL;
                external(line, arg, pid_ls, 0);
                vector_push_back(hist, line);
                free(arg);
            }
        }
    }
}

// return: 1 if &&, 2 if ||, 3 if sep
int check_logical(vector *cmd) {
    if (vector_size(cmd) < 2) {
        return 0;
    }
    for (size_t i = 0; i < vector_size(cmd); i++) {
        char *w = vector_get(cmd, i);
        if (strcmp(w, "&&") == 0) {
            return 1;
        }
        if (strcmp(w, "||") == 0) {
            return 2;
        } 
        if (w[strlen(w) - 1] == ';') {
            return 3;
        }
    }
    return 0;
}

// AND logical operation
void AND(char *line1, char *line2, char **arg1, char **arg2, vector *pid_ls) {
    fflush(stdout);
    fflush(stdin);
    // vector_push_back(hist, line1);
    pid_t pid = fork();
    if (pid < 0) {
        print_fork_failed();
        exit(1);
    } else if (pid > 0) {
        vector_push_back(pid_ls, &pid);
        print_command_executed(pid);
        int status;
        pid_t child = waitpid(pid, &status, 0);
        if (child == -1) {
            print_wait_failed();
        }
        if (WIFEXITED(status)) {
            if(WEXITSTATUS(status)) {
                print_exec_failed(line1);
                return;
            } else {
                // vector_push_back(hist, line2);
                external(line2, arg2, pid_ls, 0);
            }
        }
        // kill(child, SIGKILL);
    } else {
        int s = setpgid(0, 0);
        if (s == -1) {
            print_setpgid_failed();
        }
        execvp(arg1[0], arg1);
        exit(1);
    }
}

// OR logical operation
void OR(char *line1, char *line2, char **arg1, char **arg2, vector *pid_ls) {
    fflush(stdout);
    fflush(stdin);
    // vector_push_back(hist, line1);
    pid_t pid = fork();
    if (pid < 0) {
        print_fork_failed();
        exit(1);
    } else if (pid > 0) {
        vector_push_back(pid_ls, &pid);
        print_command_executed(pid);
        int status;
        pid_t child = waitpid(pid, &status, 0);
        if (child == -1) {
            print_wait_failed();
        }
        if (WIFEXITED(status)) {
            if(WEXITSTATUS(status)) {
                print_exec_failed(line1);
                // vector_push_back(hist, line2);
                external(line2, arg2, pid_ls, 0);
            } else {
                return;
            }
        }
        // kill(child, SIGKILL);
    } else {
        int s = setpgid(0, 0);
        if (s == -1) {
            print_setpgid_failed();
        }
        execvp(arg1[0], arg1);
        exit(1);
    }
}

// execute logical
void exe_logical(int logic, char *line, vector *pid_ls) {
    // parse logical
    vector *f_arg = char_vector_create();
    vector *s_arg = char_vector_create();
    int flag1 = 1;
    int flag2 = 0;
    for (size_t i = 0; i < strlen(line); i++) {
        if (line[i] == '&' || line[i] == '|') {
            flag1 = 0;
        }
        if (line[i] == ';') {
            flag1 = 0;
        }
        if (flag1) {
            vector_push_back(f_arg, &line[i]);
        }
        if (flag2) {
            vector_push_back(s_arg, &line[i]);
        }
        if (flag1 == 0 && isspace(line[i])) {
            flag2 = 1;
        }
    }
    // store first and second arg
    char *first  = calloc(vector_size(f_arg) + 1, 1);
    char *second  = calloc(vector_size(s_arg) + 1, 1);
    for (size_t i = 0; i < vector_size(f_arg); i++) {
        strncat(first, vector_get(f_arg, i), 1);
    }
    for (size_t i = 0; i < vector_size(s_arg); i++) {
        strncat(second, vector_get(s_arg, i), 1);
    }
    // get new argvs
    sstring *sstr1 = cstr_to_sstring(first);
    sstring *sstr2 = cstr_to_sstring(second);
    vector *v1 = sstring_split(sstr1, ' ');
    vector *v2 = sstring_split(sstr2, ' ');
    char **arg1 = calloc(vector_size(v1) + 1, sizeof(char *));
    char **arg2 = calloc(vector_size(v2) + 1, sizeof(char *));
    for (size_t i = 0; i < vector_size(v1); i++) {
        arg1[i] = vector_get(v1, i);
    }
    arg1[vector_size(v1)] = NULL;
    for (size_t i = 0; i < vector_size(v2); i++) {
        arg2[i] = vector_get(v2, i);
    }
    arg2[vector_size(v2)] = NULL;

    // start executing
    if (logic == 1) {
        AND(first, second, arg1, arg2, pid_ls);
    } else if (logic == 2) {
        OR(first, second, arg1, arg2, pid_ls);
    } else {
        external(first, arg1, pid_ls, 0);
        external(second, arg2, pid_ls, 0);
    }

    // cleanup memory
    free(arg1);
    free(arg2);
    free(first);
    free(second);
    vector_destroy(f_arg);
    vector_destroy(s_arg);
    sstring_destroy(sstr1);
    sstring_destroy(sstr2);
    vector_destroy(v1);
    vector_destroy(v2);
}

// signal handler
void sig_handler(int n) {}

int shell(int argc, char *argv[]) {
    // TODO: This is the entry point for your shell.

    // handle improper usage
    if (argc != 1 && argc != 3 && argc != 4) {
        print_usage();
        exit(1);
    }

    // get curdir
    char *path = get_current_dir_name();

    // -f and -h mode flags 
    int opt = 0;
    int f = 0;
    int h = 0;
    while((opt = getopt(argc, argv, "fh")) != -1) {
        switch(opt) {
            case 'f':
                f = 1;
                break;
            case 'h':
                h = 1;
                break;
            default:
                break;
        }
    }

    // history vector
    int hist_start = 0;
    vector *hist = string_vector_create();

    // open file in -h mode
    if (h) {
        char *path_txt = calloc(strlen(path) + strlen(argv[argc - 1]) + 2, 1);
        strcat(path_txt, path);
        strcat(path_txt, "/");
        strcat(path_txt, argv[argc - 1]);
        FILE *fptr = fopen(path_txt, "a+");
        while (!feof(fptr)) {
            char *line = NULL;
            size_t n = 0;
            ssize_t line_size = getline(&line, &n, fptr);
            if (line_size != -1) {
                line[strlen(line) - 1] = '\0';
            }
            vector_push_back(hist, line);
            free(line);
            hist_start++;
        }
        // vector_pop_back(hist);
        // hist_start--;
        fclose(fptr);
        free(path_txt);
    }

    // child pid
    vector *child_pid = int_vector_create();

    // handle interrupt
    signal(SIGINT, sig_handler);

    // execution in normal and -f mode
    if (f) {
        char *path_txt = calloc(strlen(path) + strlen(argv[argc - 1]) + 2, 1);
        strcat(path_txt, path);
        strcat(path_txt, "/");
        strcat(path_txt, argv[argc - 1]);
        FILE *fptr = fopen(path_txt, "a+");
        while (!feof(fptr)) {
            char *line = NULL;
            size_t n = 0;
            ssize_t line_size = getline(&line, &n, fptr);
            if (line_size == -1) {
                if (!vector_empty(child_pid)) {
                    for (size_t i = 0; i < vector_size(child_pid); i++) {
                        kill((pid_t)vector_get(child_pid, i), SIGKILL);
                    }
                }
                free(line);
                break;
            }
            line[strlen(line) - 1] = '\0';
            vector *cmd = read_cmd(line);
            // print info
            prompt();
            print_command(line);
            // execute
            int logic = check_logical(cmd);
            if (logic) {
                vector_push_back(hist, line);
                exe_logical(logic, line, child_pid);
            } else {
                exe_cmd(line, cmd, hist, child_pid);
            }
            // reap zombies off
            waitpid(-1, NULL, WNOHANG);
            // clean up heap
            vector_destroy(cmd);
            free(line);
        }
        if (!vector_empty(child_pid)) {
            for (size_t i = 0; i < vector_size(child_pid); i++) {
                kill((pid_t)vector_get(child_pid, i), SIGKILL);
            }
        } 
        fclose(fptr);
        free(path_txt);
    } else {
        while(1) {
            // prompt
            prompt();
            // read command
            char *line = NULL;
            size_t n = 0;
            ssize_t line_size = getline(&line, &n, stdin);
            if (line_size == -1) {
                // EOF
                if (feof(stdin)) {
                    if (!vector_empty(child_pid)) {
                        for (size_t i = 0; i < vector_size(child_pid); i++) {
                            kill((pid_t)vector_get(child_pid, i), SIGKILL);
                        }
                    } 
                    vector_resize(child_pid, 0);  
                    break;
                }
            }
            line[strlen(line) - 1] = '\0';
            vector *cmd = read_cmd(line);
            // exit
            if (strcmp(line, "exit") == 0) {
                // clean up memory
                vector_destroy(cmd);
                free(line);
                if (!vector_empty(child_pid)) {
                    for (size_t i = 0; i < vector_size(child_pid); i++) {
                        kill((pid_t)vector_get(child_pid, i), SIGKILL);
                    }
                } 
                vector_resize(child_pid, 0);
                break;
            }
            // execute
            int logic = check_logical(cmd);
            if (logic) {
                vector_push_back(hist, line);
                exe_logical(logic, line, child_pid);
            } else {
                exe_cmd(line, cmd, hist, child_pid);
            }
            // reap zombies off
            waitpid(-1, NULL, WNOHANG);
            // cleanup heap
            vector_destroy(cmd);
            free(line);
        } 
    }
    
    // update history file in -h mode
    if (h) {
        char *path_txt = calloc(strlen(path) + strlen(argv[argc - 1]) + 2, 1);
        strcat(path_txt, path);
        strcat(path_txt, "/");
        strcat(path_txt, argv[argc - 1]);
        FILE *fptr = fopen(path_txt, "a+");
        for (size_t j = hist_start; j < vector_size(hist); j++) {
            fprintf(fptr, "%s\n", vector_get(hist, j));
        }
        fclose(fptr);
        free(path_txt);
    } 

    vector_destroy(hist);  
    vector_destroy(child_pid);
    free(path);
    return 0;
}

