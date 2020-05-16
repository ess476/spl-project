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

    printf("open(\"/etc/passwd\", O_RDRW)... ");
    fflush(stdout);
    open("/etc/passwd", O_RDWR);
    
    
    return 0;
}
