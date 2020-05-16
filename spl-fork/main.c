#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include "spl.h"
#include <time.h>
#include <sys/wait.h>

int main(int argc, char* argv[])
{
    printf("pledge(\"stdio rpath\")... ");
    fflush(stdout);

    if (pledge("stdio proc") != 0)
    {
        perror("pledge");
        exit(1);
    }
    
    printf("SUCCESS!\n");


    pid_t pid = fork();
    if (pid < 0)
    {
        perror("fork");
        exit(1);
    }

    if (pid == 0)
    {
        /* attempt to open a file */

        printf("in child, attempting open(\"/etc/passwd\", O_RDONLY)\n");
        open("/etc/passwd", O_RDONLY);
    }
    else
    {
        printf("spawned child with pid: %d\n", pid);

        int status; 
        pid_t rc = waitpid(-1, &status, 0);
        if (rc < 0)
        {
            perror("waitpid");
            exit(1);
        }

        if (WIFSIGNALED(status))
        {
            extern const char * const sys_siglist[];
            printf("child stopped by signal: %d (%s)\n", WTERMSIG(status), sys_siglist[WTERMSIG(status)]);
        }
        else
        {
            printf("child exited cleanly. something went wrong.\n");
        }
        
    }
    
    
    return 0;
}
