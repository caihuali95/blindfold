#!/usr/bin/python3

import time
import subprocess
import sys
import os

RESULT_HOME = "./Results"
os.system("mkdir -p " + RESULT_HOME)

SEC_TO_MICROSEC = 1000000

def run_binary(ROUNDS, binary_path, daemon, save_output, cpus):
    command = ['taskset', '-c', cpus] + [binary_path]
    print(command)
    total_time = 0
    if not daemon:
        for i in range(ROUNDS):
            print("Running binary for round %d" % i)
            start_time = time.perf_counter()
            process = subprocess.Popen(command)
            process.wait()
            end_time = time.perf_counter()
            if process.returncode == 0:
                latency = (end_time - start_time) * SEC_TO_MICROSEC
                total_time += latency
                print(f"Round {i} latency: {latency} microseconds")
            else:
                print(f"Round {i} failed with return code {process.returncode}")
                return
    else:
        command.extend(["-r", str(ROUNDS)])
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0
        )
        byte = process.stdout.read(1)
        for i in range(ROUNDS):
            print("Sending requests to daemon for round %d" % i)
            start_time = time.perf_counter()
            process.stdin.write(byte)
            process.stdin.flush()
            byte = process.stdout.read(1)
            end_time = time.perf_counter()
            latency = (end_time - start_time) * SEC_TO_MICROSEC
            total_time += latency
            print(f"Round {i} latency: {latency} microseconds")
        process.wait()
        if process.returncode != 0:
            print(f"Daemon failed with return code {process.returncode}")
            return
    binary_name = binary_path.split("/")[-1]
    daemon_name = ("daemon" if daemon else "non-daemon") + "_" + binary_name
    print(f"Average latency of {daemon_name}: {total_time / ROUNDS} microseconds")
    if save_output != "":
        print("Saving output to file")
        outName = RESULT_HOME + "/" + save_output + "_" + daemon_name + "_avg"
        with open(outName, "w") as f:
            print(f"Average latency of {daemon_name}: {total_time / ROUNDS} microseconds", file = f)
        print("Output saved to file " + outName)

def print_usage():
    print("Usage: test_app.py <N> <binary_path> [-r] [-s nat|non|sen] [-p cpus]")
    sys.exit(1)

def main():
    if len(sys.argv) < 3 or not sys.argv[1].isdigit():
        print_usage()
    ROUNDS = int(sys.argv[1])
    binary_path = sys.argv[2]
    daemon = False
    save_output = ""
    cpus = "1,2,3"
    for i in range(3, len(sys.argv)):
        if sys.argv[i] == "-r":
            daemon = True
        elif sys.argv[i] == "-s" and i + 1 < len(sys.argv):
            save_output = sys.argv[i + 1]
        elif sys.argv[i] == "-p" and i + 1 < len(sys.argv):
            cpus = sys.argv[i + 1]
    if save_output == "":
        print("Warning for evalution: No output will be saved")
    elif save_output not in ["nat", "non", "sen"]:
        print_usage()
    run_binary(ROUNDS, binary_path, daemon, save_output, cpus)

if __name__ == '__main__':
    main()