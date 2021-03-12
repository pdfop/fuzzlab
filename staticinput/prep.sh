echo core >/proc/sys/kernel/core_pattern
echo "Set Pattern"
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
echo "Set Scaling"
