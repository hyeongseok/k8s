#!/usr/bin/env bash

USERNAME=romanze
USER_PASSWORD=romanze
GROUPNAME=romanze
ROOT_NAME=kubeadmin
ROOT_PASSWORD=kubeadmin
EXISTING_USERNAME=ubuntu
USER_UID=1000
USER_GID=1000

export DEBIAN_FRONTEND=noninteractive
echo "[TASK 1] Setup local hostname"
tee -a /etc/hosts >/dev/null <<EOF
172.30.0.16 k8s-c01-ha01
172.30.0.17 k8s-c01-ha02
172.30.0.20 k8s-c01-ha
172.30.0.11 k8s-c01-m01
172.30.0.12 k8s-c01-m02
172.30.0.13 k8s-c01-m03
172.30.0.21 k8s-c01-w01
172.30.0.22 k8s-c01-w02
172.30.0.23 k8s-c01-w03
EOF
resolvectl flush-caches
setNormalUser() {
  if [ $(id -nu $USER_UID) ]; then
    username=$(id -nu $USER_UID);
    if [ "$username" = "$EXISTING_USERNAME" ]; then
      groupmod -n ${GROUPNAME} ubuntu
      usermod -l ${USERNAME} ubuntu
      usermod -d /home/${USERNAME} -m ${USERNAME}
      echo "${USERNAME}:${USER_PASSWORD}" | chpasswd
    fi
  fi
}

masterCopyConfig() {
  mkdir -p /root/.kube /home/$USERNAME/.kube
  cp /etc/kubernetes/admin.conf /root/.kube/config
  cp /etc/kubernetes/admin.conf /home/$USERNAME/.kube/config
  chown $USERNAME:$GROUPNAME /home/$USERNAME/.kube/config
}

enableSSHLogin() {
  sed -i 's/^PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config
  sed -i 's/^KbdInteractiveAuthentication no/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config
  echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
  echo 'PubkeyAuthentication no' >> /etc/ssh/sshd_config
  systemctl reload sshd
}

setRootPassword() {
  echo -e "${ROOT_NAME}\n${ROOT_PASSWORD}" | passwd root >/dev/null 2>&1
  echo "export TERM=xterm" >> /etc/bash.bashrc
}

KEEPALIVED_CONFIG="
global_defs {
  router_id LVS_DEVEL
  script_user keepalived_script
  enable_script_security
}

vrrp_script chk_apiserver {
  script "/etc/keepalived/check_apiserver.sh"
  interval 2
  weight -2
  fall 10
  rise 2
}

vrrp_instance VI_1 {
  state MASTER
  interface eth0          # Network card  
  virtual_router_id 51
  priority %d
  authentication {
    auth_type PASS
    auth_pass 1111
  }
  unicast_src_ip %s       # The IP address of this machine
  unicast_peer {
    %s                    # The IP address of peer machines
  }
  virtual_ipaddress {
    %s                    # The VIP address
  }

  track_script {
    chk_apiserver
  }
}
"

HAPROXY_CONFIG="
global
  maxconn     10000
  user        haproxy
  group       haproxy
  daemon
  
  stats socket /var/lib/haproxy/stats

defaults
  log global
  option  httplog
  option  dontlognull
        timeout connect 5000
        timeout client 50000
        timeout server 50000

#listen stats
#  bind *:8404
#  stats enable
#  stats uri /monitor
#  stats refresh 5s

frontend kube-apiserver
  bind    *:6443
  mode    tcp                
  option  tcplog
  default_backend kube-apiserver

backend kube-apiserver
  mode tcp
  option tcplog
  option tcp-check
  balance roundrobin  
    server k8s-c01-m01 172.30.0.11:6443 check fall 3 rise 2
    server k8s-c01-m02 172.30.0.12:6443 check fall 3 rise 2
    server k8s-c01-m03 172.30.0.13:6443 check fall 3 rise 2
"

if [[ $(hostname) =~ .*ha.* ]]; then
  echo "[TASK 2] Enable ssh password authentication"
  enableSSHLogin 
  echo "[TASK 3] Set root password"
  setRootPassword
  echo "[TASK 4] Install keepalived and haproxy"
  apt-get install -qq -y keepalived haproxy >/dev/null 2>&1
  sleep 20  
  adduser --disabled-login --no-create-home --system --shell /bin/false keepalived_script >/dev/null 2>&1
  tee /etc/keepalived/check_apiserver.sh >/dev/null <<EOF
#!/bin/sh
errorExit() {
  echo "*** $@" 1>&2
  exit 1
}

curl --silent --max-time 2 --insecure https://localhost:6443/ -o /dev/null || errorExit "Error GET https://localhost:6443/"
if ip addr | grep -q 172.16.16.100; then
  curl --silent --max-time 2 --insecure https://172.30.0.20:6443/ -o /dev/null || errorExit "Error GET https://172.30.0.20:6443/"
fi
EOF
  sudo chmod +x /etc/keepalived/check_apiserver.sh
  if [[ $(hostname) =~ .*ha01.* ]]; then
    printf "${KEEPALIVED_CONFIG}" 100 172.30.0.16 172.30.0.17 172.30.0.20/24 | tee /etc/keepalived/keepalived.conf >/dev/null
  fi
  if [[ $(hostname) =~ .*ha02.* ]]; then
    printf "${KEEPALIVED_CONFIG}" 99 172.30.0.17 172.30.0.16 172.30.0.20/24 | tee  /etc/keepalived/keepalived.conf >/dev/null
  fi
  echo "$HAPROXY_CONFIG" | tee /etc/haproxy/haproxy.cfg >/dev/null
  systemctl enable haproxy --now >/dev/null 2>&1
  systemctl enable keepalived --now >/dev/null 2>&1
fi

if [[ $(hostname) =~ .*m.* || $(hostname) =~ .*w.* ]]; then
  echo "[TASK 2] Install containerd runtime"
  apt-get install -qq -y apt-transport-https ca-certificates curl gnupg lsb-release >/dev/null
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
    $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  apt-get update -qq >/dev/null
  apt-get install -qq -y containerd.io >/dev/null
  containerd config default > /etc/containerd/config.toml
  sed -i 's/SystemdCgroup \= false/SystemdCgroup \= true/g' /etc/containerd/config.toml
  systemctl restart containerd >/dev/null
  systemctl enable containerd --now >/dev/null
  echo "[TASK 3] Set up kubernetes repo"
  curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.29/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.29/deb/ /' > /etc/apt/sources.list.d/kubernetes.list
  echo "[TASK 4] Install Kubernetes components (kubeadm, kubelet and kubectl)"
  apt-get update -qq >/dev/null
  apt-get install -qq -y kubeadm kubelet kubectl >/dev/null
  # echo 'KUBELET_EXTRA_ARGS="--fail-swap-on=false"' > /etc/default/kubelet
  systemctl restart kubelet
  echo "[TASK 5] Enable ssh password authentication"
  enableSSHLogin 
  echo "[TASK 6] Set root password"
  setRootPassword
fi

if [[ $(hostname) =~ .*m.* ]]; then
  echo "[TASK 7] Rename ubuntu user"
  setNormalUser
  echo "[TASK 8] Pull required containers"
  kubeadm config images pull >/dev/null 2>&1
  if [[ $(hostname) =~ .*m01.* ]]; then
    echo "[TASK 9] Running a background script to restart haproxy"
    apt-get install -qq -y sshpass >/dev/null 2>&1
    while ! grep successfully /root/kubeinit.log >/dev/null 2>&1; do sleep 50; sshpass -p ${ROOT_PASSWORD} >/dev/null 2>&1 ssh -T k8s-c01-ha01 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "systemctl restart haproxy"; done &
    echo "[TASK 10] Initialize Kubernetes Cluster Master 01"
    # kubeadm init --pod-network-cidr=192.168.0.0/16 --ignore-preflight-errors=all >> /root/kubeinit.log 2>&1  
    kubeadm init --control-plane-endpoint="172.30.0.20:6443" \
      --upload-certs --apiserver-advertise-address=172.30.0.11 \
      --pod-network-cidr=192.168.0.0/16 \
      --ignore-preflight-errors=all >> /root/kubeinit.log 2>&1  
    echo "[TASK 11] Copy kube admin config to root user and $USERNAME user .kube directory"      
    masterCopyConfig
    echo "[TASK 12] Deploy Calico network"
    kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/tigera-operator.yaml >/dev/null
    kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/custom-resources.yaml >/dev/null
    echo "[TASK 13] Patching kube-proxy configMap, maxPerCore: 0"
    kubectl get cm/kube-proxy -n kube-system -o yaml | sed -e 's/maxPerCore:.*/maxPerCore: 0/' | kubectl apply -f - >/dev/null 2>&1
    echo "[TASK 14] Generate and save cluster join command to /joinclusterworker.sh and /joinclustercontrolplane.sh"
    joinCommand=$(kubeadm token create --print-join-command 2>/dev/null)
    echo "$joinCommand --ignore-preflight-errors=all" > /joinclusterworker.sh
    certificateKey=$(kubeadm init phase upload-certs --upload-certs | grep -vw -e certificate -e Namespace 2>/dev/null)
    echo "$joinCommand --control-plane --certificate-key $certificateKey --ignore-preflight-errors=all" > /joinclustercontrolplane.sh
  fi
  if [[ $(hostname) =~ .*m02.* || $(hostname) =~ .*m03.* ]]; then  
    echo "[TASK 9] Join a Control-plane node to Kubernetes Cluster"
    apt-get install -qq -y sshpass >/dev/null 2>&1
    sshpass -p "${ROOT_PASSWORD}" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no k8s-c01-m01.lxd:/joinclustercontrolplane.sh /joinclustercontrolplane.sh 2>/tmp/joinclustercontrolplane.log
    bash /joinclustercontrolplane.sh >> /tmp/joinclustercontrolplane.log 2>&1    
    echo "[TASK 10] Copy kube admin config to root user and $USERNAME user .kube directory"
    masterCopyConfig
  fi
fi

if [[ $(hostname) =~ .*w.* ]]; then
  echo "[TASK 7] Join a Worker node to Kubernetes Cluster"
  apt-get install -qq -y sshpass >/dev/null 2>&1
  sshpass -p "${ROOT_PASSWORD}" scp -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no k8s-c01-m01.lxd:/joinclusterworker.sh /joinclusterworker.sh 2>/tmp/joincluster.log
  bash /joinclusterworker.sh >> /tmp/joinclusterworker.log 2>&1
fi