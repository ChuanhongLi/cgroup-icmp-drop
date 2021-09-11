# Test environments
* CentOS Linux release 8.4.2105 
* mount cgroup2 : 
* 	mkdir /mnt/cgroup2
*	mount -t cgroup2 none /mnt/cgroup2/

/*
 *The cgroup2 FS must also be mounted, which by default is mounted on /sys/fs/cgroup/unified. 
 *If it’s not, you can mount it with sudo mkdir /mnt/cgroup2 && sudo mount -t cgroup2 none /mnt/cgroup2
 *the above comments are from https://nfil.dev/coding/security/ebpf-firewall-with-cgroups/
 */

# Usage
	./main 

