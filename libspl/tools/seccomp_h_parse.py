calls = []
def parse(path):
    lprefix = '#define __NR_'
    cprefix = '__NR_'

    f = open(path, 'r')

    for line in f.readlines():

        if line.startswith(lprefix):
            tokens = line.split()

            call = tokens[1][len(cprefix):]
            if not call.startswith('SCMP'):
                calls.append(call)

#parse("/usr/include/seccomp.h")
parse("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")

print('\n'.join(sorted(list(set(calls)))))