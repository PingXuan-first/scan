#!/bin/bash

# 定义日志文件
LOGFILE="rootkit_check.log"
echo "Rootkit 检查开始 - $(date)" > $LOGFILE

# 检查内核模块
echo "检查可疑内核模块..." | tee -a $LOGFILE
lsmod > modules.txt
if grep -E "taint|unknown" modules.txt; then
    echo "警告：发现可疑模块!" | tee -a $LOGFILE
    cat modules.txt | grep -E "taint|unknown" >> $LOGFILE
fi

# 检查隐藏进程
echo "检查隐藏进程..." | tee -a $LOGFILE
ps aux > ps_output.txt
for pid in /proc/[0-9]*; do
    pid=$(basename $pid)
    if ! grep -q "$pid" ps_output.txt; then
        echo "警告：发现隐藏进程 PID: $pid" | tee -a $LOGFILE
    fi
done

# 检查网络连接
echo "检查可疑网络连接..." | tee -a $LOGFILE
ss -tuln > net_output.txt
if grep -E ":[0-9]{1,5}.*LISTEN" net_output.txt | grep -vE "22|80|443"; then
    echo "警告：发现异常监听端口!" | tee -a $LOGFILE
    grep -E ":[0-9]{1,5}.*LISTEN" net_output.txt | grep -vE "22|80|443" >> $LOGFILE
fi

# 检查 SUID 文件
echo "检查异常 SUID 文件..." | tee -a $LOGFILE
find / -perm -4000 -type f 2>/dev/null > suid_files.txt
if grep -vE "/bin|/usr/bin|/sbin" suid_files.txt; then
    echo "警告：发现非标准 SUID 文件!" | tee -a $LOGFILE
    grep -vE "/bin|/usr/bin|/sbin" suid_files.txt >> $LOGFILE
fi

# 检查关键文件完整性
echo "检查核心工具完整性..." | tee -a $LOGFILE
for binary in /bin/ls /bin/ps /bin/netstat; do
    if [ -f "$binary" ]; then
        stat "$binary" >> $LOGFILE
        strings "$binary" | grep -iE "http|rootkit|hack" && echo "警告：$binary 可能被篡改!" | tee -a $LOGFILE
    fi
done

# 检查日志中的异常登录
echo "检查异常登录..." | tee -a $LOGFILE
if [ -f /var/log/auth.log ]; then
    grep "Failed password" /var/log/auth.log | tail -n 5 >> $LOGFILE
fi

echo "检查完成 - $(date)" | tee -a $LOGFILE
echo "结果已保存至 $LOGFILE"
