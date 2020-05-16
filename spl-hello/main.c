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

int main(int argc, char* argv[])
{
    printf("pledge(\"stdio rpath\")... ");
    fflush(stdout);

    if (pledge("stdio rpath") != 0)
    {
        perror("pledge");
        exit(1);
    }
    printf("SUCCESS!\n");

    int rc = -1;

    printf("opening /etc/passwd... ");
    fflush(stdout);
    rc = open("/etc/passwd", O_RDONLY);
    if (rc < 0) 
    {
        perror("open");
        exit(1);
    }
    printf("SUCCESS!\n");

    printf("pledge(\"stdio\")... ");
    fflush(stdout);
    if (pledge("stdio") != 0)
    {
        perror("pledge");
        exit(1);
    }
    printf("SUCCESS!\n");

    printf("opening /etc/passwd... ");
    fflush(stdout);
    open("/etc/passwd", O_RDONLY);
    
    return 0;
}
