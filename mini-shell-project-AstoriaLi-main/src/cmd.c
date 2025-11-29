// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* TODO: Execute cd. */
	// Sanity check
	// if no argument, return 0
	if (dir == NULL){
		return 0;
	}

	// Build complete path
    char path[1024] = "";
    word_t *current_part = dir;
    
    while (current_part) {
        // Environment variable expansion
        if (current_part->expand) {
            const char *value = getenv(current_part->string);
            if (value)
                strcat(path, value);
        } else {
            strcat(path, current_part->string);
        }
        current_part = current_part->next_part;
    }

    if (chdir(path) != 0) {
        fprintf(stderr, "Error: no such file or directory\n");
        return 1;
    }
	return 0;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* TODO: Execute exit/quit. */
	exit(0);
}

// Environment variable expansion
static char* get_word_str(word_t *word){
	if (word == NULL) return NULL;

	// Calculate required length
    size_t len = 0;
    word_t *current = word;
    
    while (current){
        if (current->expand) {
            char *val = getenv(current->string);
            len += val ? strlen(val) : 0;
        } else if (current->string) {
            len += strlen(current->string);
        }
        current = current->next_part;
    }

	// Allocate and fill buffer
    char *result = malloc(len + 1);
    if (!result)
        return NULL;
        
    result[0] = '\0';
    current = word;
    
    while (current != NULL) {
        if (current->expand) {
            char *val = getenv(current->string);
            if (val)
                strcat(result, val);
        } else if (current->string) {
            strcat(result, current->string);
        }
        current = current->next_part;
    }
    
    return result;
}

// Environment variable assignment
static int env_assignment(word_t *verb){
	if (verb == NULL || verb->next_part == NULL)
        return 0;
        
    word_t *equal = verb->next_part;
	int cmp = strcmp(equal->string, "=");
    if (cmp != 0) return 0;
        
    char *name = (char *)verb->string;
    
    // Get value after "="
    // First, calculate length needed
    size_t len = 0;
    word_t *part = equal->next_part;
    
    while (part) {
        if (part->expand) {
            char *env_val = getenv(part->string);
            len += env_val ? strlen(env_val) : 0;
        } else if (part->string) {
            len += strlen(part->string);
        }
        part = part->next_part;
    }
    
    // Allocate buffer for the value
    char *full_value = malloc(len + 1);
    if (!full_value)
        return 1;
    
    full_value[0] = '\0';
    
    // Fill the buffer
    part = equal->next_part;
    while (part) {
        if (part->expand) {
            char *env_val = getenv(part->string);
            if (env_val)
                strcat(full_value, env_val);
        } else if (part->string) {
            strcat(full_value, part->string);
        }
        part = part->next_part;
    }

	// Set environment variable
    setenv(name, full_value, 1);
    free(full_value);
    return 0;
}

static void redirections_setup(simple_command_t *s){
	// Input redirection
    if (s->in) {
        char *input_file = get_word_str(s->in);
        int fd = open(input_file, O_RDONLY);
        
        if (fd < 0) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        
        dup2(fd, STDIN_FILENO);
        close(fd);
        free(input_file);
    }

	// Output redirection
    int fd = -1;
    if (s->out) {
        char *output_file = get_word_str(s->out);
        int flags = O_WRONLY | O_CREAT;
        
        // Check for append mode
        if (s->io_flags & IO_OUT_APPEND)
            flags |= O_APPEND;
        else
            flags |= O_TRUNC;
            
        fd = open(output_file, flags, 0644);
        
        if (fd < 0) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        
        dup2(fd, STDOUT_FILENO);
        // close(fd);
        free(output_file);
    }

	// Error redirection
    /*
    if (s->err != NULL) {
        char *error_file = get_word_str(s->err);
        int flags = O_WRONLY | O_CREAT;
        
        // Check for append mode
        if (s->io_flags & IO_ERR_APPEND)
            flags |= O_APPEND;
        else
            flags |= O_TRUNC;
            
        int fd = open(error_file, flags, 0644);
        
        if (fd < 0) {
            perror("open");
            exit(EXIT_FAILURE);
        }
        
        dup2(fd, STDERR_FILENO);
        close(fd);
        free(error_file);
    }
    */
    if (s->err) {
        char *error_file = get_word_str(s->err);
        
        // Check if stderr should go to the same file as stdout
        // This handles &> redirection
        if (fd != -1 && s->out != NULL) {
            // Compare the output and error filenames
            char *output_file = get_word_str(s->out);
            if (strcmp(output_file, error_file) == 0) {
                // They point to the same file, so redirect stderr to the same fd
                dup2(fd, STDERR_FILENO);
                free(output_file);
                free(error_file);
            } else {
                // Different files, handle normally
                free(output_file);
                int flags = O_WRONLY | O_CREAT;
                
                if (s->io_flags & IO_ERR_APPEND)
                    flags |= O_APPEND;
                else
                    flags |= O_TRUNC;
                    
                int fd1 = open(error_file, flags, 0644);
                
                if (fd1 < 0) {
                    perror("open");
                    exit(EXIT_FAILURE);
                }
                
                dup2(fd1, STDERR_FILENO);
                close(fd1);
                free(error_file);
            }
        } else {
            // No stdout redirection, handle stderr normally
            int flags = O_WRONLY | O_CREAT;
            
            if (s->io_flags & IO_ERR_APPEND)
                flags |= O_APPEND;
            else
                flags |= O_TRUNC;
                
            int fd1 = open(error_file, flags, 0644);
            
            if (fd1 < 0) {
                perror("open");
                exit(EXIT_FAILURE);
            }
            
            dup2(fd1, STDERR_FILENO);
            close(fd1);
            free(error_file);
        }
    }
    
    // Close stdout_fd if it was opened
    if (fd != -1)
        close(fd);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* TODO: Sanity checks. */
	if (s == NULL || s->verb == NULL)
        return 1;

	// Complete word command in verb (including expansion)
	char *verb_str = get_word_str(s->verb);
	if (!verb_str) return 1;

	/* TODO: If builtin command, execute the command. */
	int is_cd = strcmp(s->verb->string, "cd") == 0;
    int is_pwd = strcmp(s->verb->string, "pwd") == 0;
    int is_exit = strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0;
    
    if (is_cd || is_pwd || is_exit) {
        // Save original file descriptors
        int saved_stdin = dup(STDIN_FILENO);
        int saved_stdout = dup(STDOUT_FILENO);
        int saved_stderr = dup(STDERR_FILENO);
        
        // Set up redirections
        redirections_setup(s);
        
        int status = 0;
        
        // Execute the builtin command
        if (is_cd) {
            status = shell_cd(s->params);
        } else if (is_pwd) {
            char buf[100];
            if (getcwd(buf, 100) != NULL) {
                printf("%s\n", buf);
                fflush(stdout);
            } else {
                perror("pwd");
                status = 1;
            }
        } else if (is_exit) {
            shell_exit();
        }
        
        // Restore original file descriptors
        dup2(saved_stdin, STDIN_FILENO);
        dup2(saved_stdout, STDOUT_FILENO);
        dup2(saved_stderr, STDERR_FILENO);
        close(saved_stdin);
        close(saved_stdout);
        close(saved_stderr);
        
        free(verb_str);
        return status;
    }

	/* TODO: If variable assignment, execute the assignment and return
	 * the exit status.
	 */
	if (s->verb->next_part != NULL && strcmp(s->verb->next_part->string, "=") == 0) {
        int status = env_assignment(s->verb);
        free(verb_str);
        return status;
    }

	/* TODO: If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */
	pid_t child_pid = fork();
	if (child_pid < 0){
		perror("fork");
        free(verb_str);
        return 1;
	}
	else if (child_pid == 0){ // Child process
		redirections_setup(s);

		word_t *w = s->params;
		int i = 1;

		while (w != NULL) {
            i++;
            w = w->next_word;
        }
        
        char **argv = malloc((i + 1) * sizeof(char *));
        if (!argv) {
            perror("malloc");
            exit(1);
        }
        
        argv[0] = verb_str;
        int j = 1;
        w = s->params;
        
        while (w && j < i) {
            argv[j] = get_word_str(w); // Get environment variable expansion
            w = w->next_word;
            j++;
        }
        
        argv[j] = NULL;

		if (execvp(argv[0], argv) < 0) {
            fprintf(stderr, "Execution failed for '%s'\n", argv[0]);
            exit(1);
        }
	}

	// Parent process
	free(verb_str);
	
	// Wait for child
	int status;
	waitpid(child_pid, &status, 0);
	return WEXITSTATUS(status);
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Execute cmd1 and cmd2 simultaneously. */
	pid_t pid1, pid2;
    int status1 = 0, status2 = 0;
    
    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        return false;
    }
    
    if (pid1 == 0) {
        // Child process for cmd1
        exit(parse_command(cmd1, level + 1, father));
    }
    
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        // Clean up first child
        waitpid(pid1, NULL, 0);
        return false;
    }
	
	if (pid2 == 0) {
        // Child process for cmd2
        exit(parse_command(cmd2, level + 1, father));
    }
    
    // Parent waits for both children
    waitpid(pid1, &status1, 0);
    waitpid(pid2, &status2, 0);
    
    // Return true if both commands succeeded
    return (WEXITSTATUS(status1) == 0 && WEXITSTATUS(status2) == 0);
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	/* TODO: Redirect the output of cmd1 to the input of cmd2. */
	int pipefd[2];
    pid_t pid1, pid2;
    int status1, status2;
    
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return false;
    }
    
    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        close(pipefd[READ]);
        close(pipefd[WRITE]);
        return false;
    }

	if (pid1 == 0) {
        // Child process for cmd1
        close(pipefd[READ]);

        // Redirect stdout to the pipe
        dup2(pipefd[WRITE], STDOUT_FILENO);
        close(pipefd[WRITE]);
        
        exit(parse_command(cmd1, level + 1, father));
    }
    
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        close(pipefd[READ]);
        close(pipefd[WRITE]);
        waitpid(pid1, NULL, 0);
        return false;
    }

	if (pid2 == 0) {
        // Child process for cmd2
        close(pipefd[WRITE]);

        // Redirect stdin from the pipe
        dup2(pipefd[READ], STDIN_FILENO);
        close(pipefd[READ]);
        
        exit(parse_command(cmd2, level + 1, father));
    }
    
    // Parent closes both ends of the pipe
    close(pipefd[READ]);
    close(pipefd[WRITE]);
    
    // Wait for both children
    waitpid(pid1, &status1, 0);
    waitpid(pid2, &status2, 0);
    
    // Return the exit status of the second command
    return (WEXITSTATUS(status2) == 0);
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* TODO: sanity checks */
	if (c == NULL)
        return SHELL_EXIT;
    
    int status;

	if (c->op == OP_NONE) {
		/* TODO: Execute a simple command. */
		if (c->scmd)
            return parse_simple(c->scmd, level, c);
        return 1;
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* TODO: Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
        status = parse_command(c->cmd2, level + 1, c);
        return status;

	case OP_PARALLEL:
		/* TODO: Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level, c) ? 0 : 1;

	case OP_CONDITIONAL_NZERO:
		/* TODO: Execute the second command only if the first one
		 * returns non zero.
		 */
		status = parse_command(c->cmd1, level + 1, c);
		if (status != 0)
			return parse_command(c->cmd2, level + 1, c);
		return status;

	case OP_CONDITIONAL_ZERO:
		/* TODO: Execute the second command only if the first one
		 * returns zero.
		 */
		status = parse_command(c->cmd1, level + 1, c);
		if (status == 0)
			return parse_command(c->cmd2, level + 1, c);
		return status;

	case OP_PIPE:
		/* TODO: Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level, c) ? 0 : 1;

	default:
		return SHELL_EXIT;
	}

	return 1; /* TODO: Replace with actual exit code of command. */
}
