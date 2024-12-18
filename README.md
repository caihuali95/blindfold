# Blindfold

## Overview

This repository provides a proof-of-concept implementation of Blindfold.
Blindfold protects sensitive user application data from the untrusted operating system, mainly leveraging a trusted software called Guardian running at a higher privilege level.

## Prerequisites
- Raspberry Pi 4 Model B with 8GB DRAM
- TF card
- [Raspberry Pi Imager](https://www.raspberrypi.com/software/)
- This github repo

## Usage
### 1. Preparation
1. Install Raspberry Pi OS on the TF card with [Raspberry Pi Imager](https://www.raspberrypi.com/software/).

    We tested the following steps on Raspberry Pi 4 (RPI4) using Raspberry Pi OS Lite (64-bit) released on 2024-11-19.
2. Set up user name and password. We assume the user name is "usr" in the following steps.

    To use a different user name, please change line 29 of device/rpi/flash.sh of this repo accordingly.
3. Install [Rust](https://www.rust-lang.org/tools/install).
4. Clone this repo to local and enter the Blindfold folder.
5. Build Blindfold and flash the TF card.
    ```bash
    sudo apt install make gcc flex bison gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libssl-dev -y
    cd ./device/rpi
    ./build.sh
    sudo ./flash.sh
    ```
6. Boot up RPI4 with the TF card, connect it to ethernet, and build benchmark. Do not run this command with root privilege.
    ```bash
    ./run_me.sh
    ```

### 2. Evaluation
Evaluation on native Linux:
1. Run LMbench and print the aggregative results.
    ```bash
    ./batch_test_lmbench.sh nat
    ./print_lmbench_result.py nat
    ```
2. Run LTP system call testcases.
    ```bash
    ./test_syscalls.py -n
    ```
3. Evaluate app latency, e.g., run OTP for 100 times.
    ```bash
    ./test_app.py 100 ./otp
    ```
4. Run other application, e.g., test fork/clone/futex/signal.
    ```bash
    ./test
    ```
5. Nano benchmark of mode switching overhead.
    Before measurement, please uncomment line 48~56 of linux/arch/arm64/kernel/entry.S, rebuild and reflash the linux kernel. Please uncomment this code only for nano benchmark as it is unsafe. After reflash and reboot, run the following command:
    ```bash
    ./nano -n
    ```
Evaluation with Blindfold enabled:
1. Enable Blindfold. This command has to be run with root privilege.
    ```bash
    sudo ./run_me.sh
    ```
2. Run LMbench and print the aggregative results.

    2.1 For non-sensitive configuration:
    ```bash
    ./batch_test_lmbench.sh non
    ./print_lmbench_result.py non
    ```
    2.2 For sensitive configuration:
    ```bash
    ./batch_test_lmbench.sh sen
    ./print_lmbench_result.py sen
    ```
3. Run LTP system call testcases.
    ```bash
    ./test_syscalls.py -a
    ```
4. Evaluate app latency, e.g., run OTP for 100 times.

    4.1 For non-sensitive configuration:
    ```bash
    ./test_app.py 100 ./otp
    ```
    4.2 For sensitive configuration:
    ```bash
    ./test_app.py 100 ./adapted_otp
    ```
5. Run other application, e.g., test fork/clone/futex/signal.

    5.1 For non-sensitive configuration:
    ```bash
    ./test
    ```
    5.2 For sensitive configuration:
    ```bash
    ./adapted_test
    ```

## License
GPL-2.0 License
