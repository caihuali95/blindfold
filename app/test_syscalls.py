#!/usr/bin/python3

import os
from os import listdir
from os.path import isdir, isfile, join
import subprocess
import sys

if len(sys.argv) > 1 and sys.argv[1] == "-h":
    print("Usage:")
    print("\t%s -h\n\t\tPrint usage\n" % sys.argv[0])
    print("\t%s -p\n\t\tLTP preparation\n" % sys.argv[0])
    print("\t%s -c\n\t\tCount test folders/files\n" % sys.argv[0])
    print("\t%s -s folder [-b/n/a]\n\t\tStart from a specific folder\n" % sys.argv[0])
    print("\t%s -t folder [-b/n/a]\n\t\tTest only one specific folder\n" % sys.argv[0])
    print("\t%s -t folder -f file [-b/n/a]\n\t\tTest only one specific file\n" % sys.argv[0])
    print("\t-b: Compile but not run\n")
    print("\t-n: Test only on native linux\n")
    print("\t-a: Test w/o re-compilation\n")
    exit(0)

directory = "./ltp/testcases/kernel/syscalls"
folders = [f for f in listdir(directory) if isdir(join(directory, f))]
if len(sys.argv) > 1 and sys.argv[1] == "-p":
    p = subprocess.Popen(["find", "./ltp", "-exec", "touch", "{}", "+"])
    p.wait()
    top = os.getcwd()
    os.chdir("./ltp")
    p = subprocess.Popen(["make", "clean"])
    p.wait()
    p = subprocess.Popen(["make", "autotools"])
    p.wait()
    p = subprocess.Popen(["./configure"])
    p.wait()
    os.chdir("./lib")
    p = subprocess.Popen(["make"])
    p.wait()
    os.chdir(top)
    os.system("mkdir -p ./log_ltp")
    print("# of folders = %d" % len(folders))
    print(folders)
    exit(0)

just_count = just_build = just_native = no_build = False
start_folder = target_folder = target_file = ""
if len(sys.argv) > 1:
    if sys.argv[1] == "-c":                             # count test folders & files
        just_count = True
    if sys.argv[1] == "-s":                             # start from a specific folder
        start_folder = sys.argv[2]
    if sys.argv[1] == "-t":                             # test a specific folder
        target_folder = sys.argv[2]
        if len(sys.argv) > 3 and sys.argv[3] == "-f":   # test a specific file
            target_file = sys.argv[4]
    if sys.argv[len(sys.argv) - 1] == "-b":             # build ELF files only but not test
        just_build = True
    if sys.argv[len(sys.argv) - 1] == "-n":             # build ELF files and test on native environment but not adapt
        just_native = True
    if sys.argv[len(sys.argv) - 1] == "-a":             # do not build ELF files but adapt and test
        no_build = True
    if sys.argv[len(sys.argv) - 1] == "-na":            # do not build ELF files or adapt but test on non-sensitive environment
        just_native = True
        no_build = True

skip_folders = ["cma", "sigaltstack", "clone3", "mremap", "io_uring", "prctl", "keyctl", "mq_notify"]
skip_folders.extend([])
skip_files = ["kill11", "abort01", "waitid10", "waitpid05", "futex_cmp_requeue01", "epoll-ltp", "fork06", "fork12", "mmap05", "mmap13", "mprotect04", "close_range02"]
skip_files.extend([])
# cma (process_vm_readv and process_vm_writev) can not be supported by Blindfold's design
# sigaltstack, clone3, mremap are not supported by Blindfold's prototype as we are lazy
# io_uring, prctl, keyctl and mq_notify are operation specific and not supported
# kill11, abort01, waitid10 and waitpid05 dump core, which accesses user space without capability
# futex_cmp_requeue01, epoll-ltp, fork06 and fork12 runs out of system resources and crashes the test
# mmap05, mmap13 and mprotect04 use siglongjmp, which is not supported
# close_range02 uses clone3, which is not supported

if just_count or just_build:
    skip_folders = []
    skip_files = []
if just_native:
    skip_folders = []
    skip_files = ["fork12"]
if target_folder != "":
    skip_folders = []
if target_file != "":
    skip_files = []

pass_file_list_n = list()
fail_file_list_n = list()
skip_file_list_n = list()
warn_file_list_n = list()
pass_file_list_s = list()
fail_file_list_s = list()
skip_file_list_s = list()
warn_file_list_s = list()
not_match_list = list()

total_test_folder = 0
total_test_file = match_test_file = 0
count_case_n = [0 for i in range(4)]
count_case_s = [0 for i in range(4)]
skip = False if start_folder == "" else True
for folder in folders:
    if folder == start_folder:
        skip = False
    if skip or folder in skip_folders or target_folder != "" and folder != target_folder:
        continue
    total_test_folder += 1
    print("test folder: %s" % folder)
    subdir = join(directory, folder)
    os.system("rm -f %s/adapted_*" % subdir)
    if not no_build:
        os.system("make -C %s clean" % subdir)
        os.system("chmod 664 %s/*" % subdir)
        os.system("make -C %s" % subdir)
    os.system("file %s/*" % subdir)
    if just_build:
        continue
    for file in listdir(subdir):
        if file in skip_files or target_file != "" and file != target_file:
            continue
        filepath = join(subdir, file)
        if isfile(filepath) and os.access(filepath, os.X_OK):
            total_test_file += 1
            print("test file: " + file)
            if just_count:
                continue
            cmd = "%s 2>&1 | tee ./log_ltp/%s.log" % (filepath, file)
            print(cmd)
            os.system(cmd)
            tmp_count_case_n = [0 for i in range(4)]
            with open("./log_ltp/%s.log" % file, 'r') as log:
                for line in log:
                    if line.find('TPASS') != -1:
                        tmp_count_case_n[0] += 1
                    if line.find('TFAIL') != -1:
                        tmp_count_case_n[1] += 1
                    if line.find('TBROK') != -1:
                        tmp_count_case_n[2] += 1
                    if line.find('TWARN') != -1:
                        tmp_count_case_n[3] += 1
            # print after processing each file
            print("-----------------------------------------------------------")
            print("# of test cases for %s = %d" % (file, sum(tmp_count_case_n)))
            print("passed test cases\t = %d" % tmp_count_case_n[0])
            print("failed test cases\t = %d" % tmp_count_case_n[1])
            print("broken test cases\t = %d" % tmp_count_case_n[2])
            print("warned test cases\t = %d" % tmp_count_case_n[3])
            for i in range(4):
                count_case_n[i] += tmp_count_case_n[i]
            if tmp_count_case_n[3] > 0:
                warn_file_list_n.append(file)
                print("%s has warnings" % file)
            if tmp_count_case_n[2] > 0 or tmp_count_case_n[1] > 0:
                fail_file_list_n.append(file)
                print("%s broken or failed" % file)
            elif tmp_count_case_n[0] > 0:
                pass_file_list_n.append(file)
                print("%s passed" % file)
            else:
                skip_file_list_n.append(file)
                print("%s skipped" % file)
            if just_native:
                continue

            cmd = "./adapter %s" % filepath
            print(cmd)
            os.system(cmd)
            filepath = join(subdir, "adapted_" + file)
            os.system("chmod +x " + filepath)

            cmd = "%s 2>&1 | tee ./log_ltp/%s.retro_log" % (filepath, file)
            print(cmd)
            os.system(cmd)
            tmp_count_case_s = [0 for i in range(4)]
            with open("./log_ltp/%s.retro_log" % file, 'r') as log:
                for line in log:
                    if line.find('TPASS') != -1:
                        tmp_count_case_s[0] += 1
                    if line.find('TFAIL') != -1:
                        tmp_count_case_s[1] += 1
                    if line.find('TBROK') != -1:
                        tmp_count_case_s[2] += 1
                    if line.find('TWARN') != -1:
                        tmp_count_case_s[3] += 1
            # print after processing each file
            print("-----------------------------------------------------------")
            print("# of test cases for %s = %d" % (file, sum(tmp_count_case_s)))
            print("passed test cases\t = %d" % tmp_count_case_s[0])
            print("failed test cases\t = %d" % tmp_count_case_s[1])
            print("broken test cases\t = %d" % tmp_count_case_s[2])
            print("warned test cases\t = %d" % tmp_count_case_s[3])
            for i in range(4):
                count_case_s[i] += tmp_count_case_s[i]
            if tmp_count_case_s[3] > 0:
                warn_file_list_s.append(file)
                print("%s has warnings" % file)
            if tmp_count_case_s[2] > 0 or tmp_count_case_s[1] > 0:
                fail_file_list_s.append(file)
                print("%s broken or failed" % file)
            elif tmp_count_case_s[0] > 0:
                pass_file_list_s.append(file)
                print("%s passed" % file)
            else:
                skip_file_list_s.append(file)
                print("%s skipped" % file)

            not_match = False
            for i in range(4):
                not_match |= tmp_count_case_n[i] != tmp_count_case_s[i]
            if not_match:
                not_match_list.append(file)
                print("%s does not match" % file)
                os.system("file %s" % filepath)
            else:
                match_test_file += 1
    # print after processing each folder
    print("--------------------------------------------------------------------------------")
    print("# of test files so far: match vs total = %d vs %d" % (match_test_file, total_test_file))
    print("# of test cases so far = %d" % sum(count_case_n))
    print("passed test cases\t = %d" % count_case_n[0])
    print("failed test cases\t = %d" % count_case_n[1])
    print("broken test cases\t = %d" % count_case_n[2])
    print("warned test cases\t = %d" % count_case_n[3])
    print("# of test cases so far = %d" % sum(count_case_s))
    print("passed test cases\t = %d" % count_case_s[0])
    print("failed test cases\t = %d" % count_case_s[1])
    print("broken test cases\t = %d" % count_case_s[2])
    print("warned test cases\t = %d" % count_case_s[3])
# print after processing all folders
print("# of test folders = %d" % total_test_folder)
print("# of test files = %d" % total_test_file)
print("fail_list_n = %s" % fail_file_list_n)
print("warn_list_n = %s" % warn_file_list_n)
print("skip_list_n = %s" % skip_file_list_n)
print("fail_list_s = %s" % fail_file_list_s)
print("warn_list_s = %s" % warn_file_list_s)
print("skip_list_s = %s" % skip_file_list_s)
print("not_match_list = %s" % not_match_list)
