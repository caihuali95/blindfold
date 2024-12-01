#!/usr/bin/python3

import os
import sys

RESULT_HOME = "./Results"
os.system("mkdir -p " + RESULT_HOME)

LM_RESULT_DIR = "./lmbench_results"

def print_usage():
    print("Usage: python3 gen_lmbench_result.py nat|non|sen")
    sys.exit(1)

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ["nat", "non", "sen"]:
        print_usage()
    environment = sys.argv[1]
    result_dir = LM_RESULT_DIR + "/" + environment
    output_file = RESULT_HOME + "/" + environment + "_lmbench_avg"
    command = "cat " + result_dir + "/*_avg 2>&1 | tee " + output_file
    print(command)
    os.system(command)

if __name__ == '__main__':
    main()