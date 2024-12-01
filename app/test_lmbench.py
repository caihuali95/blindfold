#!/usr/bin/python3

import os
import sys

LM_RESULT_DIR = "./lmbench_results"
os.system("mkdir -p " + LM_RESULT_DIR)

BIN = "./lmbench_bin/"
FILE = "./data/bvlc_googlenet.caffemodel"
W = 100
N = 10
R = 10

def lat_syscall(prefix, retrofit):
    cmds = ["null", "read", "write", "stat", "open"]
    for cmd in cmds:
        command = BIN + retrofit + "lat_syscall -W " + str(W) + " -N " + str(N) + " " + cmd
        if cmd == "stat" or cmd == "open":
            command = command + " " + FILE
        total = 0
        for i in range(R):
            outName = prefix + "_lat_syscall_" + cmd + "_" + "{:0>3}".format(i)
            final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
            print(final)
            os.system(final)
            with open(outName, 'r') as file:
                line = file.readline()
                words = line.split()
                if len(words) != 4 or words[0] != "Simple" or words[3] != "microseconds":
                    print("Error: " + outName)
                    sys.exit(1)
                latency = float(words[2])
                total += latency
        avg = total / R
        print("Average of " + cmd + " = " + str(avg) + " microseconds")
        outName = prefix + "_lat_syscall_" + cmd + "_" + "avg"
        with open(outName, 'w') as file:
            file.write("Average of " + cmd + " = " + str(avg) + " microseconds\n")

def lat_select(prefix, retrofit):
    command = BIN + retrofit + "lat_select -W " + str(W) + " -N " + str(N) + " -n 100 file"
    total = 0
    for i in range(R):
        outName = prefix + "_lat_select_" + "{:0>3}".format(i)
        final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
        print(final)
        os.system(final)
        with open(outName, 'r') as file:
            line = file.readline()
            words = line.split()
            if len(words) != 6 or words[0] != "Select" or words[5] != "microseconds":
                print("Error: " + outName)
                sys.exit(1)
            latency = float(words[4])
            total += latency
    avg = total / R
    print("Average of select = " + str(avg) + " microseconds")
    outName = prefix + "_lat_select_" + "avg"
    with open(outName, 'w') as file:
        file.write("Average of select = " + str(avg) + " microseconds\n")

def lat_proc(prefix, retrofit):
    cmds = ["fork", "exec"]
    for cmd in cmds:
        command = BIN + retrofit + "lat_proc -W " + str(W) + " -N " + str(N) + " " + cmd
        total = 0
        for i in range(R):
            outName = prefix + "_lat_proc_" + cmd + "_" + "{:0>3}".format(i)
            final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
            print(final)
            os.system(final)
            with open(outName, 'r') as file:
                line = file.readline()
                words = line.split()
                if len(words) != 4 or words[0] != "Process" or words[3] != "microseconds":
                    print("Error: " + outName)
                    sys.exit(1)
                latency = float(words[2])
                total += latency
        avg = total / R
        print("Average of " + cmd + " = " + str(avg) + " microseconds")
        outName = prefix + "_lat_proc_" + cmd + "_" + "avg"
        with open(outName, 'w') as file:
            file.write("Average of " + cmd + " = " + str(avg) + " microseconds\n")

def lat_pagefault(prefix, retrofit):
    command = BIN + retrofit + "lat_pagefault -W " + str(W) + " -N " + str(N) + " " + FILE
    total = 0
    for i in range(R):
        outName = prefix + "_lat_pagefault_" + "{:0>3}".format(i)
        final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
        print(final)
        os.system(final)
        with open(outName, 'r') as file:
            line = file.readline()
            words = line.split()
            if len(words) != 5 or words[0] != "Pagefaults" or words[4] != "microseconds":
                print("Error: " + outName)
                sys.exit(1)
            latency = float(words[3])
            total += latency
    avg = total / R
    print("Average of pagefault = " + str(avg) + " microseconds")
    outName = prefix + "_lat_pagefault_" + "avg"
    with open(outName, 'w') as file:
        file.write("Average of pagefault = " + str(avg) + " microseconds\n")

def lat_ctx(prefix, retrofit):
    command = BIN + retrofit + "lat_ctx -W " + str(W) + " -N " + str(N) + " -s 0 2"
    total = 0
    for i in range(R):
        outName = prefix + "_lat_ctx_" + "{:0>3}".format(i)
        final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
        print(final)
        os.system(final)
        with open(outName, 'r') as file:
            line1 = file.readline()
            line2 = file.readline()
            line3 = file.readline()
            words = line3.split()
            if len(words) != 2 or words[0] != "2":
                print("Error: " + outName)
                sys.exit(1)
            latency = float(words[1])
            total += latency
    avg = total / R
    print("Average of ctx = " + str(avg) + " microseconds")
    outName = prefix + "_lat_ctx_" + "avg"
    with open(outName, 'w') as file:
        file.write("Average of ctx = " + str(avg) + " microseconds\n")

def lat_sig(prefix, retrofit):
    cmds = ["install", "catch"]
    for cmd in cmds:
        command = BIN + retrofit + "lat_sig -W " + str(W) + " -N " + str(N) + " " + cmd
        total = 0
        for i in range(R):
            outName = prefix + "_lat_sig_" + cmd + "_" + "{:0>3}".format(i)
            final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
            print(final)
            os.system(final)
            with open(outName, 'r') as file:
                line = file.readline()
                words = line.split()
                if len(words) != 5 or words[0] != "Signal" or words[4] != "microseconds":
                    print("Error: " + outName)
                    sys.exit(1)
                latency = float(words[3])
                total += latency
        avg = total / R
        print("Average of " + cmd + " = " + str(avg) + " microseconds")
        outName = prefix + "_lat_sig_" + cmd + "_" + "avg"
        with open(outName, 'w') as file:
            file.write("Average of " + cmd + " = " + str(avg) + " microseconds\n")

def lat_unix(prefix, retrofit):
    command = BIN + retrofit + "lat_unix -W " + str(W) + " -N " + str(N)
    total = 0
    for i in range(R):
        outName = prefix + "_lat_unix_" + "{:0>3}".format(i)
        final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
        print(final)
        os.system(final)
        with open(outName, 'r') as file:
            line = file.readline()
            words = line.split()
            if len(words) != 6 or words[0] != "AF_UNIX" or words[5] != "microseconds":
                print("Error: " + outName)
                sys.exit(1)
            latency = float(words[4])
            total += latency
    avg = total / R
    print("Average of AF_UNIX = " + str(avg) + " microseconds")
    outName = prefix + "_lat_unix_" + "avg"
    with open(outName, 'w') as file:
        file.write("Average of AF_UNIX = " + str(avg) + " microseconds\n")

def lat_pipe(prefix, retrofit):
    command = BIN + retrofit + "lat_pipe -W " + str(W) + " -N " + str(N)
    total = 0
    for i in range(R):
        outName = prefix + "_lat_pipe_" + "{:0>3}".format(i)
        final = "taskset -c 1,2,3 " + command + " 2>&1 | tee " + outName
        print(final)
        os.system(final)
        with open(outName, 'r') as file:
            line = file.readline()
            words = line.split()
            if len(words) != 4 or words[0] != "Pipe" or words[3] != "microseconds":
                print("Error: " + outName)
                sys.exit(1)
            latency = float(words[2])
            total += latency
    avg = total / R
    print("Average of pipe = " + str(avg) + " microseconds")
    outName = prefix + "_lat_pipe_" + "avg"
    with open(outName, 'w') as file:
        file.write("Average of pipe = " + str(avg) + " microseconds\n")

def prepare(environment, executable):
    if environment == "nat":
        RESULT_DIR = LM_RESULT_DIR + "/nat"
        print("mkdir -p " + RESULT_DIR)
        os.system("mkdir -p " + RESULT_DIR)
        return ""
    elif environment == "non":
        RESULT_DIR = LM_RESULT_DIR + "/non"
        print("mkdir -p " + RESULT_DIR)
        os.system("mkdir -p " + RESULT_DIR)
        return ""
    elif environment == "sen":
        RESULT_DIR = LM_RESULT_DIR + "/sen"
        print("mkdir -p " + RESULT_DIR)
        os.system("mkdir -p " + RESULT_DIR)
        print("./adapter " + BIN + executable)
        os.system("./adapter " + BIN + executable)
        os.system("chmod +x " + BIN + "adapted_" + executable)
        return "adapted_"

def print_usage():
    print("Usage: python3 test_lmbench.py nat|non|sen\n" + \
          "\t\t[-W <warmup>] [-N <repetitions>] [-R <# of tests>]\n" + \
          "\t\t[lat_syscall|lat_select|lat_proc|lat_pagefault|lat_ctx|lat_sig|lat_unix|lat_pipe]")
    sys.exit(1)

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ["nat", "non", "sen"]:
        print_usage()
    environment = sys.argv[1]
    for i in range(2, len(sys.argv) - 1):
        if sys.argv[i] == "-W":
            if not sys.argv[i + 1].isdigit():
                print_usage()
            global W
            W = int(sys.argv[i + 1])
        elif sys.argv[i] == "-N":
            if not sys.argv[i + 1].isdigit():
                print_usage()
            global N
            N = int(sys.argv[i + 1])
        elif sys.argv[i] == "-R":
            if not sys.argv[i + 1].isdigit():
                print_usage()
            global R
            R = int(sys.argv[i + 1])
    if sys.argv[len(sys.argv) - 1] == "lat_syscall":
        retrofit = prepare(environment, "lat_syscall")
        lat_syscall(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    elif sys.argv[len(sys.argv) - 1] == "lat_select":
        retrofit = prepare(environment, "lat_select")
        lat_select(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    elif sys.argv[len(sys.argv) - 1] == "lat_proc":
        retrofit = prepare(environment, "lat_proc")
        lat_proc(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    elif sys.argv[len(sys.argv) - 1] == "lat_pagefault":
        retrofit = prepare(environment, "lat_pagefault")
        lat_pagefault(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    elif sys.argv[len(sys.argv) - 1] == "lat_ctx":
        retrofit = prepare(environment, "lat_ctx")
        lat_ctx(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    elif sys.argv[len(sys.argv) - 1] == "lat_sig":
        retrofit = prepare(environment, "lat_sig")
        lat_sig(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    elif sys.argv[len(sys.argv) - 1] == "lat_unix":
        retrofit = prepare(environment, "lat_unix")
        lat_unix(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    elif sys.argv[len(sys.argv) - 1] == "lat_pipe":
        retrofit = prepare(environment, "lat_pipe")
        lat_pipe(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
    else:
        retrofit = prepare(environment, "lat_syscall")
        lat_syscall(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
        retrofit = prepare(environment, "lat_select")
        lat_select(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
        retrofit = prepare(environment, "lat_proc")
        lat_proc(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
        retrofit = prepare(environment, "lat_pagefault")
        lat_pagefault(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
        retrofit = prepare(environment, "lat_sig")
        lat_sig(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
        retrofit = prepare(environment, "lat_unix")
        lat_unix(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
        retrofit = prepare(environment, "lat_pipe")
        lat_pipe(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)
        retrofit = prepare(environment, "lat_ctx")
        lat_ctx(LM_RESULT_DIR + "/" + environment + "/" + environment, retrofit)

if __name__ == '__main__':
    main()
