#!/usr/bin/env bash
# ulp-driver: create a Fedora 44 libvirt VM for kernel/driver development.
#
# Usage: provision_fkernel_vm.sh <vm-name> [ip] [mac]
#   VM_DISK_DIR   where the qcow2 image goes (default /var/lib/libvirt/images)
#   VM_SSH_KEY    public key injected for root (default ~/.ssh/id_ed25519.pub)
#   VM_RAM_MB, VM_VCPUS, VM_DISK_SIZE   sizing (defaults 8192, 4, 40G)
set -euo pipefail

VM_NAME="${1:?usage: $0 <vm-name> [ip] [mac]}"
VM_IP="${2:-}"
VM_MAC="${3:-52:54:00:$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n' | sed 's/../&:/g;s/:$//')}"
DISK_PATH="${VM_DISK_DIR:-/var/lib/libvirt/images}/${VM_NAME}.qcow2"
SSH_KEY="${VM_SSH_KEY:-${HOME}/.ssh/id_ed25519.pub}"
DISK_SIZE="${VM_DISK_SIZE:-40G}"
RAM_MB="${VM_RAM_MB:-8192}"
VCPUS="${VM_VCPUS:-4}"

if [ -n "$VM_IP" ]; then
    echo "=== Reserving DHCP IP ${VM_IP} for ${VM_NAME} ==="
    sudo virsh net-update default add ip-dhcp-host \
        "<host mac='${VM_MAC}' name='${VM_NAME}' ip='${VM_IP}' />" --config --live || true
fi

echo "=== Building ${DISK_SIZE} Fedora 44 image at ${DISK_PATH} ==="
sudo virt-builder fedora-44 \
    --output "${DISK_PATH}" \
    --format qcow2 \
    --size "${DISK_SIZE}" \
    --hostname "${VM_NAME}" \
    --ssh-inject "root:file:${SSH_KEY}" \
    --run-command "ssh-keygen -A" \
    --selinux-relabel

sudo chown qemu:qemu "${DISK_PATH}"

echo "=== Creating domain ${VM_NAME} ==="
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

echo "=== ${VM_NAME} created and booting ==="
