# audit daemon
logs security related events.

## audit rules

### Control rules
changes audit system configuration

### File system rules
catches files events
```bash
auditctl -w path_to_file -p permissions -k key_name
```

* path_to_file is the file or directory that is audited.

* permissions are the permissions that are logged:
    r — read access to a file or a directory.\
    w — write access to a file or a directory.\
    x — execute access to a file or a directory.\
    a — change in the file's or directory's attribute.

* key_name is an optional string that helps you identify which rule or a set of rules generated a particular log entry.

Example 
```
auditctl -w /sbin/insmod -p x -k module_insertion
```
### System call rules
catches syscall events

```
sudo auditctl -a always,exit -F arch=b64 -S write -k write_to_file
```

Syscalls names can be found at `find / -name unistd_64.h 2>/dev/null`

#### for specific executables
```
auditctl  -a action,filter [ -F arch=cpu -S system_call] -F exe=path_to_executable_file -k key_name
```