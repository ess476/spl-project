import csv
import sys
from collections import defaultdict

groups = defaultdict(list)
c2g = {}

genC = True


with open(sys.argv[1], newline='') as csvfile:
    r = -1

    reader = csv.reader(csvfile, delimiter=',')
    for row in reader:
        
        r += 1
        if r == 1:
            for c in range(len(row)):
                g = row[c]
                groups[g] = []
                c2g[c] = g
        elif r >= 3:
            for c in range(len(row)):
                sysc = row[c]
                if len(sysc) > 0:
                    groups[c2g[c]].append(sysc)




not_done = []

if genC:

    for g in groups:
        print("int _" + g + "_stub(scmp_filter_ctx ctx)")
        print("{")


        print("\t/* simple rules */")
        ndcur = []
        for sysc in groups[g]:
            if sysc.startswith('__'):
                not_done.append(sysc)
                ndcur.append(sysc)
                continue
            print("\tALLOW(" + sysc + ");")

        print("")
        print("")
        print("\t/* complex rules */")

        print("")
        for sysc in ndcur:
            print("\t/* " + sysc[2:] + " */")

        print("}")
        print("\n")

    print("")
    print("")
    print("")

    print("/* group table */")
    print("static const pledge_t pledge_table[] = ")
    print("{")

    gtext = ['\t{{"{}", _{}_stub}}'.format(g, g) for g in groups]
    print(',\n'.join(gtext))

    print("};")

else:
    for g in groups:
        print("-------------------" + g + "-------------------")

        for sysc in groups[g]:
            if sysc.startswith('__'):
                not_done.append(sysc)
                continue
            print("ALLOW(" + sysc + ")")

        
        print("-----------------------------------------------")
        print()


print("-------------------not done-------------------")
print(', '.join(not_done))
