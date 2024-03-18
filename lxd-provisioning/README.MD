> Tested on Ubuntu 22.04

### Setting up K8S Cluster using LXC/LXD

|First IP|Last IP|Utilization|Description|
|:-:|:-:|:-:|-|
|172.30.0.1||1|Network Gateway
|172.30.0.2|172.30.0.3||Gateway Redundancy Protocol like VRRP or HSRP
|172.30.0.4|172.30.0.10||Future Needs
|172.30.0.11|172.30.0.15|3|Control Plane Nodes
|172.30.0.16|172.30.0.19|2|Load Balancer using Keepalived and HAProxy
|172.30.0.20||1|Load Balancer IP Virtual
|172.30.0.21|172.30.0.40|3|Worker Nodes
|172.30.0.41|172.30.0.70||Next Cluster

### Firewall Rules

```sh
# Without these ufw rules, your containers will not get IP addresses 
# from the LXD DHCP server, and there won’t be any networking.
sudo ufw allow in on lxdbr0 comment 'lxdbr0 for LXD'
Rules updated

sudo ufw route allow in on lxdbr0 comment 'lxdbr0 for LXD'
Rules updated
Rules updated (v6)

sudo ufw route allow out on lxdbr0 comment 'lxdbr0 for LXD'
Rules updated
Rules updated (v6)

sudo ufw reload
Firewall reloaded
```

#### Haproxy and Keepalived Nodes
```sh
...
```

#### Master Nodes

|Protocol|Direction|Port Range|Purpose|Used By|
|:-:|:-:|:-:|-|-|
|TCP|Inbound|6443*|Kubernetes API Server|All
|TCP|Inbound|2379-2380|etcd server client API|kube-apiserver,etcd
|TCP|Inbound|10250|Kubelet API|Self,Control Plane
|TCP|Inbound|10251|kube-scheduler|Self
|TCP|Inbound|10252|kube-controller-manager|Self

```sh
# Only on the master nodes
# This rules for VM
sudo ufw allow in ssh 
sudo ufw allow in 6443/tcp
sudo ufw allow from 172.30.0.0/24
sudo ufw default allow outgoing
sudo ufw default deny incoming
sudo ufw enable
```

#### Worker Nodes

|Protocol|Direction|Port Range|Purpose|Used By|
|:-:|:-:|:-:|-|-|
|TCP|Inbound|10250|Kubelet API|Self,Control Plane
|TCP|Inbound|30000-32767|NodePort Services|All

```sh
# Only on the worker nodes
# This rules for VM
sudo ufw allow in ssh 
sudo ufw allow from 172.30.0.0/24
sudo ufw allow in 30000:32767/tcp
sudo ufw allow in 30000:32767/udp
sudo ufw default allow outgoing
sudo ufw default allow routed
sudo ufw default deny incoming
sudo ufw --force enable
```

### LXC Containers Resources

|Qty|Name|Description|vCPU|Memory|Disk 01|Disk 02|
|:-:|-|-|:-:|:-:|:-:|:-:|
|2|k8s-c01-ha01/02|Load Balancer entre Worker e Control Plane Nodes|4|4GB|100GB|-|
|3|k8s-c01-m01/02/03|Control Plane Nodes|4|4GB|100GB|-|
|3|k8s-c01-w01/02/03|Workers Nodes|8|8GB|100GB|200GB|

### Creating node for k8s cluster

```sh
./provision
Usage: provision [create|delete]
```
```sh
./provision create
Creating Kubernetes Cluster.

Are you sure (Y/n)?

==> Bringing up k8s-c01-ha01
Creating k8s-c01-ha01
Starting k8s-c01-ha01
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Enable ssh password authentication
[TASK 3] Set root password
[TASK 4] Install keepalived and haproxy

==> Bringing up k8s-c01-ha02
Creating k8s-c01-ha02
Starting k8s-c01-ha02
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Enable ssh password authentication
[TASK 3] Set root password
[TASK 4] Install keepalived and haproxy

==> Bringing up k8s-c01-m01
Creating k8s-c01-m01
Starting k8s-c01-m01
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Install containerd runtime
[TASK 3] Set up kubernetes repo
[TASK 4] Install Kubernetes components (kubeadm, kubelet and kubectl)
[TASK 5] Enable ssh password authentication
[TASK 6] Set root password
[TASK 7] Rename ubuntu user
[TASK 8] Pull required containers
[TASK 9] Running a background script to restart haproxy
[TASK 10] Initialize Kubernetes Cluster Master 01
[TASK 11] Copy kube admin config to root user and romanze user .kube directory
[TASK 12] Deploy Calico network
[TASK 13] Patching kube-proxy configMap, maxPerCore: 0
[TASK 14] Generate and save cluster join command to /joinclusterworker.sh and /joinclustercontrolplane.sh

==> Bringing up k8s-c01-m02
Creating k8s-c01-m02
Starting k8s-c01-m02
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Install containerd runtime
[TASK 3] Set up kubernetes repo
[TASK 4] Install Kubernetes components (kubeadm, kubelet and kubectl)
[TASK 5] Enable ssh password authentication
[TASK 6] Set root password
[TASK 7] Rename ubuntu user
[TASK 8] Pull required containers
[TASK 9] Join a Control-plane node to Kubernetes Cluster
[TASK 10] Copy kube admin config to root user and romanze user .kube directory

==> Bringing up k8s-c01-m03
Creating k8s-c01-m03
Starting k8s-c01-m03
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Install containerd runtime
[TASK 3] Set up kubernetes repo
[TASK 4] Install Kubernetes components (kubeadm, kubelet and kubectl)
[TASK 5] Enable ssh password authentication
[TASK 6] Set root password
[TASK 7] Rename ubuntu user
[TASK 8] Pull required containers
[TASK 9] Join a Control-plane node to Kubernetes Cluster
[TASK 10] Copy kube admin config to root user and romanze user .kube directory

==> Bringing up k8s-c01-w01
Creating k8s-c01-w01
Starting k8s-c01-w01
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Install containerd runtime
[TASK 3] Set up kubernetes repo
[TASK 4] Install Kubernetes components (kubeadm, kubelet and kubectl)
[TASK 5] Enable ssh password authentication
[TASK 6] Set root password
[TASK 7] Join a Worker node to Kubernetes Cluster

==> Bringing up k8s-c01-w02
Creating k8s-c01-w02
Starting k8s-c01-w02
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Install containerd runtime
[TASK 3] Set up kubernetes repo
[TASK 4] Install Kubernetes components (kubeadm, kubelet and kubectl)
[TASK 5] Enable ssh password authentication
[TASK 6] Set root password
[TASK 7] Join a Worker node to Kubernetes Cluster

==> Bringing up k8s-c01-w03
Creating k8s-c01-w03
Starting k8s-c01-w03
==> Running bootstrap.sh
[TASK 1] Setup local hostname
[TASK 2] Install containerd runtime
[TASK 3] Set up kubernetes repo
[TASK 4] Install Kubernetes components (kubeadm, kubelet and kubectl)
[TASK 5] Enable ssh password authentication
[TASK 6] Set root password
[TASK 7] Join a Worker node to Kubernetes Cluster
lxc list
+--------------+---------+--------------------------------+------+-----------+-----------+
|     NAME     |  STATE  |              IPV4              | IPV6 |   TYPE    | SNAPSHOTS |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-ha01 | RUNNING | 172.30.0.20 (eth0)             |      | CONTAINER | 0         |
|              |         | 172.30.0.16 (eth0)             |      |           |           |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-ha02 | RUNNING | 172.30.0.17 (eth0)             |      | CONTAINER | 0         |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-m01  | RUNNING | 192.168.78.0 (vxlan.calico)    |      | CONTAINER | 0         |
|              |         | 172.30.0.11 (eth0)             |      |           |           |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-m02  | RUNNING | 192.168.41.0 (vxlan.calico)    |      | CONTAINER | 0         |
|              |         | 172.30.0.12 (eth0)             |      |           |           |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-m03  | RUNNING | 192.168.149.64 (vxlan.calico)  |      | CONTAINER | 0         |
|              |         | 172.30.0.13 (eth0)             |      |           |           |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-w01  | RUNNING | 192.168.227.64 (vxlan.calico)  |      | CONTAINER | 0         |
|              |         | 172.30.0.21 (eth0)             |      |           |           |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-w02  | RUNNING | 192.168.118.192 (vxlan.calico) |      | CONTAINER | 0         |
|              |         | 172.30.0.22 (eth0)             |      |           |           |
+--------------+---------+--------------------------------+------+-----------+-----------+
| k8s-c01-w03  | RUNNING | 192.168.221.128 (vxlan.calico) |      | CONTAINER | 0         |
|              |         | 172.30.0.23 (eth0)             |      |           |           |
+--------------+---------+--------------------------------+------+-----------+-----------+
lxc exec k8s-c01-m01 -- kubectl get nodes
root@k8s-c01-m01:~# kubectl get nodes
NAME          STATUS   ROLES           AGE     VERSION
k8s-c01-m01   Ready    control-plane   10m     v1.29.3
k8s-c01-m02   Ready    control-plane   8m29s   v1.29.3
k8s-c01-m03   Ready    control-plane   6m20s   v1.29.3
k8s-c01-w01   Ready    <none>          4m44s   v1.29.3
k8s-c01-w02   Ready    <none>          3m25s   v1.29.3
k8s-c01-w03   Ready    <none>          2m9s    v1.29.3
```
```sh
./provision delete

Deleting Kubernetes Cluster.

Are you sure (Y/n)?

==> Deleting k8s-c01-ha01...
==> Deleting k8s-c01-ha02...
==> Deleting k8s-c01-m01...
==> Deleting k8s-c01-m02...
==> Deleting k8s-c01-m03...
==> Deleting k8s-c01-w01...
==> Deleting k8s-c01-w02...
==> Deleting k8s-c01-w03...
```

## Reference 
- [Starting the configuration of a production-ready Kubernetes cluster](https://www.linkedin.com/pulse/starting-configuration-production-ready-kubernetes-cluster-queiroz)
- [Kubernetes playground](https://github.com/justmeandopensource/kubernetes/tree/master)