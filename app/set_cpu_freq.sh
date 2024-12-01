#!/bin/sh

echo userspace > /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor
echo userspace > /sys/devices/system/cpu/cpu1/cpufreq/scaling_governor
echo userspace > /sys/devices/system/cpu/cpu2/cpufreq/scaling_governor
echo userspace > /sys/devices/system/cpu/cpu3/cpufreq/scaling_governor

echo 1800000 > /sys/devices/system/cpu/cpu0/cpufreq/scaling_setspeed
echo 1800000 > /sys/devices/system/cpu/cpu1/cpufreq/scaling_setspeed
echo 1800000 > /sys/devices/system/cpu/cpu2/cpufreq/scaling_setspeed
echo 1800000 > /sys/devices/system/cpu/cpu3/cpufreq/scaling_setspeed

echo 'current freq:'
cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_cur_freq
cat /sys/devices/system/cpu/cpu1/cpufreq/cpuinfo_cur_freq
cat /sys/devices/system/cpu/cpu2/cpufreq/cpuinfo_cur_freq
cat /sys/devices/system/cpu/cpu3/cpufreq/cpuinfo_cur_freq

echo 'max freq:'
cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq
cat /sys/devices/system/cpu/cpu1/cpufreq/cpuinfo_max_freq
cat /sys/devices/system/cpu/cpu2/cpufreq/cpuinfo_max_freq
cat /sys/devices/system/cpu/cpu3/cpufreq/cpuinfo_max_freq

echo 'isolated CPUs:'
cat /sys/devices/system/cpu/isolated
