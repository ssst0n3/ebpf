```
$ docker run -ti --cap-add CAP_SYS_ADMIN test ./hello_c/hello_c
2025/09/17 09:51:16 Waiting for events..
2025/09/17 09:51:16 uid: 0	pid: 810297	comm: iptables.sh
2025/09/17 09:51:17 uid: 0	pid: 810302	comm: iptables.sh
2025/09/17 09:51:18 uid: 0	pid: 810306	comm: iptables.sh
^C2025/09/17 09:51:19 Received signal, exiting..
```                                                                                                                                                                                                                                              
```
$ docker run -ti --cap-add CAP_SYS_ADMIN test ./hello_go/hello_go
2025/09/17 09:51:25 Waiting for events..
2025/09/17 09:51:25 execve called by UID: 0, PID: 810561, Comm: iptables.sh
2025/09/17 09:51:26 execve called by UID: 0, PID: 810565, Comm: iptables.sh
2025/09/17 09:51:27 execve called by UID: 0, PID: 810569, Comm: iptables.sh
^C2025/09/17 09:51:28 Received signal, exiting..
```
