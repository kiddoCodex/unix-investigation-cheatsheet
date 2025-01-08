# Unix Investigation Cheatsheet for Red Teamers

This **Unix Investigation Cheatsheet** is designed for red teamers conducting investigations on Unix-based operating systems. Unix-based systems include BSD variants (FreeBSD, OpenBSD, NetBSD), AIX, Solaris, and other Unix-like systems. It includes a wide range of enumeration, file system auditing, process analysis, privilege escalation techniques, and more.

---

## 1. **System Information**

### General System Info:
- **uname -a**: Display kernel name, version, architecture, and hostname.
- **hostname**: Show the system’s hostname.
- **lsb_release -a**: For systems supporting it, display distribution info (on Linux).
- **cat /etc/*release**: Display release information (on various Unix systems).
- **dmesg**: View kernel ring buffer and boot messages.

### CPU and Memory:
- **top**: Real-time system monitoring tool (displays CPU, memory, process activity).
- **vmstat**: Show system performance related to memory, processes, paging, etc.
- **free -h**: Display memory usage (on Linux).
- **ps aux**: List all running processes.
- **mpstat**: CPU usage stats (if available).
- **sar -r 1 10**: Collect memory usage statistics (requires `sysstat` package).

### Disk and Storage:
- **df -h**: Display disk space usage.
- **du -sh <path>**: Show disk usage for specific directories.
- **fdisk -l**: List partition information (may require root access).
- **lsblk**: Show block devices and storage layout.
- **mount**: Show mounted file systems.
- **ls /dev/disk/by-id/**: List disk devices by their ID.
- **smartctl -a /dev/sda**: Check disk health (requires `smartmontools`).

---

## 2. **User and Group Enumeration**

### User Accounts:
- **cat /etc/passwd**: Display all user accounts (including system users).
- **id <username>**: Show UID, GID, and groups for a specific user.
- **getent passwd**: List all user accounts (in case `/etc/passwd` is managed by NIS, LDAP, etc.).
- **w**: Show current users logged into the system.
- **who**: Show who is logged into the system.
- **last**: Display user login history.
- **finger <username>**: Show detailed information about a specific user (if available).

### Groups:
- **cat /etc/group**: Display all groups and their members.
- **getent group**: List all groups in the system.
- **groups <username>**: Show groups a user belongs to.
- **id**: Display group and user ID information.

### User Activity:
- **lastlog**: Show the last login of all users.
- **last -f /var/log/wtmp**: Display historical login information (wtmp logs).
- **last -t <time_interval>**: Filter logs by time.
- **grep <username> /var/log/auth.log**: Find authentication events for a specific user (or `/var/log/secure` on some systems).
- **grep -i <pattern> /var/log/*log**: Search for specific patterns in logs (e.g., failed logins, sudo usage).
  
---

## 3. **File System & Persistence**

### Hidden Files and Directories:
- **ls -a**: Show all files, including hidden ones (those starting with `.`).
- **find / -name ".*"**: Search for all hidden files in the filesystem.
- **find / -name "*.*" -exec file {} \;**: List file types of all files in the system, useful for identifying malicious files.
- **lsattr <file>**: View file attributes (Linux-specific, may require `e2fsprogs` package).

### System Logs:
- **/var/log/syslog**: General system activity log.
- **/var/log/messages**: System-wide messages and warnings.
- **/var/log/auth.log**: Authentication-related logs (login attempts, sudo usage).
- **/var/log/secure**: Authentication logs on some Unix systems.
- **/var/log/cron**: Cron job execution logs.
- **/var/log/boot.log**: Boot logs.
- **grep -i <pattern> /var/log/*log**: Search for specific strings in log files (e.g., login attempts, user commands).
- **journalctl**: View systemd logs (on systems using `systemd`).

### Persistence Mechanisms:
- **crontab -l**: List cron jobs for the current user.
- **crontab -u <user> -l**: List cron jobs for a specific user (requires root).
- **ls /etc/cron.d/**: Check for system-wide cron jobs.
- **ls /etc/cron.daily/**, **cron.hourly/**, **cron.weekly/**: List system cron directories.
- **find / -name "*.pl"**: Search for suspicious Perl scripts.
- **ps -aux | grep cron**: View running cron jobs.
- **cat /etc/init.d/* or ls /etc/init.d/**: Look for service scripts (init.d services).

---

## 4. **Malware Analysis & Detection**

### Analyzing Running Processes:
- **ps aux**: List all running processes.
- **top**: Real-time resource usage (CPU, memory) by processes.
- **pstree**: View processes in a tree structure.
- **lsof**: List open files, sockets, and network connections.
- **netstat -tulnp**: List listening ports and associated processes (requires root).
- **htop**: Interactive process viewer (requires installation).

### Detecting Suspicious Processes:
- **ps -ef**: Show full process listing, including command arguments.
- **ls -l /proc/*/exe**: List executable files of running processes (Linux-specific).
- **file <binary_path>**: Check file types to verify legitimacy.
- **strings <binary_path>**: Extract printable strings from binaries (look for suspicious content).
- **ldd <binary_path>**: List shared libraries used by a binary.
  
### Suspicious Files:
- **find / -type f -exec file {} \;**: Identify file types across the system.
- **find / -type f -exec sha256sum {} \;**: Compute file hashes for integrity checking.

### Kernel Modules:
- **lsmod**: List loaded kernel modules (Linux).
- **kldstat**: List loaded kernel modules (BSD).
- **ls /lib/modules/**: Directory containing kernel modules.
- **modinfo <module_name>**: Get information about a specific kernel module.
- **rmmod <module_name>**: Remove a kernel module.

---

## 5. **Privilege Escalation**

### Checking for Sudo Rights:
- **sudo -l**: List commands that the current user can run with sudo.
- **cat /etc/sudoers**: View the sudoers file (requires root access).
- **getent sudoers**: List sudo privileges.
- **sudo -u root <command>**: Run commands as the root user (if allowed).
- **ls -l /etc/sudoers.d/**: Check for additional sudo configurations.

### SUID/SGID Files:
- **find / -type f -perm -4000**: Find SUID (Set User ID) files.
- **find / -type f -perm -2000**: Find SGID (Set Group ID) files.
- **ls -l <file_path>**: Check SUID/SGID permissions of specific files.
  
### Checking for Root-owned Files:
- **find / -user root**: Find files owned by root.
- **find / -group root**: Find files belonging to the root group.

---

## 6. **Network Monitoring & Analysis**

### Active Connections and Listening Ports:
- **netstat -tuln**: List listening ports and associated services.
- **ss -tuln**: List listening ports (faster alternative to `netstat`).
- **lsof -i**: List open network connections.
- **lsof -i :<port_number>**: List processes using a specific port.
- **iftop**: Real-time network usage monitor.
- **tcpdump -i <interface>**: Capture network traffic on a specific interface.

### Investigating Services:
- **ps aux | grep <service_name>**: Check if a service is running.
- **systemctl list-units**: List all active systemd units (if systemd is used).
- **service --status-all**: List all services and their status (SysVinit-based systems).
- **netstat -nr**: Display the routing table.

---

## 7. **Forensics and Evidence Collection**

### Log Collection:
- **cp /var/log/* /path/to/exfiltrate/**: Copy logs to an external directory for analysis.
- **tar -czf logs.tar.gz /var/log/**: Archive log files.
- **logrotate**: Check for log rotation configuration (helps identify missing logs).
  
### Memory Dump:
- **dd if=/dev/mem of=/path/to/mem_dump bs=1024k**: Create a memory dump (requires root).
- **cat /proc/kcore**: Access system memory (Linux-specific).

### File Integrity Checking:
- **sha256sum <file_path>**: Generate a SHA256 hash for a file.
- **md5sum <file_path>**: Generate an MD5 hash for file integrity checking.

---

## 8. **Apple-Specific Tools (If Unix Variant Supports It)**

- **FSEvents**: Track file system events and access modifications (check `/System/Library/Logs`).
- **sysctl**: View and modify kernel parameters.
- **log show**: Query macOS logs for activity (macOS).
  
---

## Conclusion

This **Unix Investigation Cheatsheet** provides a detailed set of techniques to conduct thorough investigations on Unix-based systems. It includes methods for system enumeration, user and group analysis, process auditing, network analysis, file integrity checks, and privilege escalation. By using these techniques, red teamers and investigators can efficiently gather intelligence, detect malicious activity, and extract evidence during penetration tests or forensic investigations.

