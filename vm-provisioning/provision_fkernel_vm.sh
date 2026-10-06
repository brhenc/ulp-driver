#!/usr/bin/env bash
# ==============================================================================
# ulp-driver: Automated VM Provisioning for Fedora Rawhide Kernel Dev
# ==============================================================================
set -euo pipefail

VM_NAME="${1:-fkernel-dev}"
VM_IP="${2:-192.168.122.170}"
VM_MAC="${3:-52:54:00:fa:01:70}"
DISK_PATH="/home/vm/${VM_NAME}.qcow2"
DISK_SIZE="100G"
RAM_MB="65536"
VCPUS="64"

echo "=== 1. Reserving DHCP IP ${VM_IP} for ${VM_NAME} ==="
sudo virsh net-update default add ip-dhcp-host "<host mac='${VM_MAC}' name='${VM_NAME}' ip='${VM_IP}' />" --config --live || true

echo "=== 2. Building ${DISK_SIZE} Fedora 44 Image ==="
sudo virt-builder fedora-44 \
    --output "${DISK_PATH}" \
    --format qcow2 \
    --size "${DISK_SIZE}" \
    --hostname "${VM_NAME}" \
    --ssh-inject "root:file:/home/vm-template/gpg_id_rsa4096.pub" \
    --ssh-inject "root:file:${HOME}/.ssh/id_ed25519.pub" \
    --run-command "ssh-keygen -A" \
    --selinux-relabel

sudo chown qemu:qemu "${DISK_PATH}"

echo "=== 3. Launching Domain via virt-install ==="
sudo virt-install --name "${VM_NAME}" \
    --import \
    --noautoconsole \
    --os-variant=fedora43 \
    --memory "${RAM_MB}" \
    --vcpus "${VCPUS}" \
    --network="network=default,model=virtio,mac=${VM_MAC}" \
    --disk "path=${DISK_PATH},format=qcow2,bus=virtio" \
    --virt-type=kvm \
    --accelerate

echo "=== 4. VM ${VM_NAME} successfully created and booting ==="
