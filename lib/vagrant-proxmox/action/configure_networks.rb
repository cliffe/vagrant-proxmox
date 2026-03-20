module VagrantPlugins
  module Proxmox
    module Action

      # ConfigureNetworks reads vm.network declarations from the Vagrantfile and:
      #
      #   1. Applies NIC config to the cloned QEMU VM via the Proxmox API
      #      (net1, net2, ... with VLAN tags) — runs before the VM boots.
      #      net0 is always preserved as the Vagrant management NIC.
      #
      #   2. After the VM boots and SSH is available (ConfigureNetworksGuest),
      #      runs in-guest commands via communicate.sudo to configure IPs.
      #
      # We deliberately do NOT inject Vagrant provisioners at runtime because
      # calling vm_config.provision after config has been finalised corrupts
      # Vagrant 2.3.x's internal provisioner config state and causes a
      # TypeError during subsequent config validation passes.
      #
      # Vagrantfile usage (SecGen generates this):
      #
      #   box.vm.network :private_network, ip: "10.0.1.5",
      #                  proxmox_bridge: "vmbr0", proxmox_vlan: 100
      #
      #   box.vm.network :private_network, type: "dhcp",
      #                  proxmox_bridge: "vmbr0", proxmox_vlan: 200
      #
      class ConfigureNetworks < ProxmoxAction

        def initialize(app, env)
          @app = app
          @logger = Log4r::Logger.new 'vagrant_proxmox::action::configure_networks'
        end

        def call(env)
          machine = env[:machine]
          config = machine.provider_config
          vm_config = machine.config.vm

          unless config.vm_type == :qemu
            return next_action(env)
          end

          networks = collect_networks(vm_config, config)

          if networks.empty?
            env[:ui].detail 'No vm.network entries found; skipping network configuration.'
            return next_action(env)
          end

          env[:ui].info 'Configuring VM network interfaces via Proxmox API...'

          node, vm_id = machine.id.split('/')

          apply_nic_config(env, node, vm_id, networks, config)

          # Store for ConfigureNetworksGuest (runs after VM boots)
          env[:proxmox_networks] = networks

          env[:ui].info I18n.t('vagrant_proxmox.done')
          next_action(env)
        end

        private

        # Returns an Array of hashes, one per :private_network / :public_network.
        # Starts at net1 — net0 is always the Vagrant management NIC and must
        # be preserved from the template clone.
        def collect_networks(vm_config, provider_config)
          net_index = 1
          vm_config.networks.each_with_object([]) do |(type, opts), arr|
            next unless %i[private_network public_network].include?(type)

            net = {
              net_key: "net#{net_index}",
              type: type,
              bridge: opts[:proxmox_bridge] || provider_config.qemu_bridge,
              vlan: opts[:proxmox_vlan],
              nic_model: opts[:proxmox_nic_model] || provider_config.qemu_nic_model,
              dhcp: (opts[:type].to_s == 'dhcp' || opts[:ip].nil?),
              ip: opts[:ip],
              netmask: opts[:netmask] || '255.255.255.0',
              macaddress: opts[:mac],
            }
            arr << net
            net_index += 1
          end
        end

        # Calls PUT /nodes/{node}/qemu/{vmid}/config to set net1, net2, ...
        # net0 is explicitly preserved (it is the Vagrant management NIC).
        def apply_nic_config(env, node, vm_id, networks, provider_config)
          template_config = connection(env).get_vm_config(
            node: node, vm_id: vm_id, vm_type: provider_config.vm_type
          )

          # Find existing NICs to delete — but NEVER delete net0
          existing_nics = template_config.keys
                                         .map(&:to_s)
                                         .select { |k| k.match?(/^net\d+$/) }
                                         .reject { |k| k == 'net0' }

          params = { vmid: vm_id }

          new_net_keys = networks.map { |n| n[:net_key] }
          to_delete = existing_nics.reject { |k| new_net_keys.include?(k) }
          params[:delete] = to_delete.join(',') unless to_delete.empty?

          networks.each do |net|
            parts = [net[:nic_model].to_s]
            parts[0] += "=#{net[:macaddress]}" if net[:macaddress]
            parts << "bridge=#{net[:bridge]}"
            parts << "tag=#{net[:vlan]}" if net[:vlan]
            key = net[:net_key].to_sym
            params[key] = parts.join(',')
            env[:ui].detail "  #{net[:net_key]}: #{params[key]}"
          end

          exit_status = connection(env).config_clone(
            node: node, vm_type: provider_config.vm_type, params: params
          )
          unless exit_status == 'OK'
            raise VagrantPlugins::Proxmox::Errors::VMNetworkError,
                  error_msg: "NIC configuration failed: #{exit_status}"
          end

          # Read back NIC config from Proxmox to get assigned MAC addresses
          updated_config = connection(env).get_vm_config(
            node: node, vm_id: vm_id, vm_type: provider_config.vm_type
          )
          networks.each do |net|
            nic_string = updated_config[net[:net_key].to_sym].to_s
            mac_match = nic_string.match(/=([0-9A-Fa-f:]{17})/)
            net[:macaddress] = mac_match[1] if mac_match
          end

          # Store net0 MAC for management NIC identification
          net0_string = updated_config[:net0].to_s
          env[:ui].detail "net0 string: #{net0_string}"
          net0_mac_match = net0_string.match(/=([0-9A-Fa-f:]{17})/)
          env[:ui].detail "net0 MAC match: #{net0_mac_match.inspect}"
          env[:proxmox_management_mac] = net0_mac_match[1] if net0_mac_match

        end

      end

      # ConfigureNetworksGuest runs after StartVm, waits for SSH to become
      # available, then uses communicate.sudo to write /etc/network/interfaces
      # entries and bring up each static-IP interface.
      #
      # NIC indexing: net0 = management (already up), our NICs are net1, net2, ...
      # Inside the guest, these appear as interface index 1, 2, ... (after lo and
      # the management interface). We use /sys/class/net sorted order and skip the
      # first interface (management).
      class ConfigureNetworksGuest < ProxmoxAction

        def initialize(app, env)
          @app = app
          @logger = Log4r::Logger.new 'vagrant_proxmox::action::configure_networks_guest'
        end

        def call(env)
          networks = env[:proxmox_networks]

          unless networks && !networks.empty?
            return next_action(env)
          end

          machine = env[:machine]
          is_windows = machine.config.vm.guest == :windows
          is_win7 = machine.provider_config.qemu_template.to_s.downcase.start_with?('win7')
          static_nets = networks.reject { |net| net[:dhcp] }

          unless static_nets.empty?
            env[:ui].info 'Waiting for SSH before configuring in-guest interfaces...'

            ssh_timeout = machine.config.ssh.connect_timeout || 300
            unless machine.communicate.wait_for_ready(ssh_timeout)
              raise VagrantPlugins::Proxmox::Errors::VMNetworkError,
                    error_msg: "Timed out waiting for SSH to configure network interfaces"
            end

            env[:ui].info 'Configuring in-guest network interfaces...'

            # arr_idx is 0-based into static_nets. Guest interface index is
            # arr_idx + 1 because index 0 is the management NIC (net0).
            networks.each_with_index do |net, arr_idx|
              nic_idx = arr_idx + 1
              if is_windows
                unless net[:dhcp]
                  script = windows_ip_script(nic_idx, net[:ip], net[:netmask], net[:macaddress], is_win7)
                  env[:ui].detail "  Configuring Windows NIC #{nic_idx}: #{net[:ip]}"
                  machine.communicate.sudo(script) do |type, data|
                    env[:ui].detail "  [#{type}] #{data.chomp}" unless data.strip.empty?
                  end
                end
              else
                if net[:dhcp]
                  dhcp_script = <<~SHELL
        #!/bin/bash
        IFACE=$(ls /sys/class/net | grep -v lo | sort | sed -n '#{nic_idx + 1}p')
        cat >> /etc/network/interfaces <<EOF

        allow-hotplug $IFACE
        iface $IFACE inet dhcp
        EOF
        ifup "$IFACE" 2>/dev/null || true
      SHELL
                  machine.communicate.sudo(dhcp_script)
                else
                  script = linux_ip_script(nic_idx, net[:ip], net[:netmask])
                  env[:ui].detail "  Configuring Linux NIC #{nic_idx}: #{net[:ip]}"
                  machine.communicate.sudo(script)
                end
              end
            end

          unless is_windows
                # Pre-emptively fix /etc/network/interfaces for after net0 (eth0) removal
              # Only runs if ethX naming is in use - processes in reverse order to avoid collisions
              fix_script = <<~SHELL
                  #!/bin/bash
                  # Disable cloud-init network configuration and remove stale files
                  echo "network: {config: disabled}" > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg
                  rm -f /etc/network/interfaces.d/50-cloud-init
                  rm -f /etc/network/interfaces.d/50-cloud-init.cfg
  
                  # Remove management NIC stanzas (eth0 for Kali, ens3 for Debian)
                  sed -i '/allow-hotplug eth0/d' /etc/network/interfaces
                  sed -i '/iface eth0 inet dhcp/d' /etc/network/interfaces
                  sed -i '/auto eth0/d' /etc/network/interfaces
                  sed -i '/allow-hotplug ens3/d' /etc/network/interfaces
                  sed -i '/iface ens3 inet dhcp/d' /etc/network/interfaces
                  sed -i '/auto ens3/d' /etc/network/interfaces
  
                  # Shift ethN names down by 1 using placeholder (only applies to ethX style naming)
                  if grep -qP 'eth[1-9][0-9]*' /etc/network/interfaces; then
                    for i in $(grep -oP 'eth\\K[1-9][0-9]*' /etc/network/interfaces | sort -rn | uniq); do
                      new=$((i - 1))
                      sed -i "s/eth${i}/ETH_PLACEHOLDER_${new}/g" /etc/network/interfaces
                    done
                    sed -i "s/ETH_PLACEHOLDER_/eth/g" /etc/network/interfaces
                  fi
  
                # ensure the hostname is in /etc/hosts
                if ! grep -q "$(hostname)" /etc/hosts; then
                  echo "127.0.1.1 $(hostname)" >> /etc/hosts
                fi
  
              SHELL

              machine.communicate.sudo(fix_script)
            end

            env[:ui].info I18n.t('vagrant_proxmox.done')
          end

          next_action(env)
        end

        private

        def linux_ip_script(nic_index, ip, netmask)
          cidr = cidr_from_netmask(netmask)
          <<~SHELL
            #!/bin/bash
            set -e
            IFACE=$(ls /sys/class/net | grep -v lo | sort | sed -n '#{nic_index + 1}p')
            if [ -z "$IFACE" ]; then
              echo "ERROR: Could not find network interface at index #{nic_index}" >&2
              exit 1
            fi
            echo "Configuring $IFACE with static IP #{ip}/#{netmask}"
            if grep -q "iface $IFACE" /etc/network/interfaces 2>/dev/null; then
              TMPF=$(mktemp)
              awk "/auto $IFACE/{found=1} found && /^$/{found=0; next} !found{print}" \
                /etc/network/interfaces > "$TMPF"
              mv "$TMPF" /etc/network/interfaces
            fi
            cat >> /etc/network/interfaces <<EOF

            auto $IFACE
            iface $IFACE inet static
                address #{ip}
                netmask #{netmask}
            EOF
            ifdown "$IFACE" 2>/dev/null || true
            ifup "$IFACE" 2>/dev/null || (ip addr add #{ip}/#{cidr} dev "$IFACE" && ip link set "$IFACE" up)
          SHELL
        end

        def windows_ip_script(nic_index, ip, netmask, mac, is_win7)
          if is_win7
            windows_ip_script_win7(nic_index, ip, netmask, mac)
          else
            windows_ip_script_server(nic_index, ip, netmask, mac)
          end
        end


        def windows_ip_script_win7(nic_index, ip, netmask, mac)
          mac_windows = mac.upcase
          <<~PS1
    $allAdapters = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.MACAddress -ne $null }
    foreach ($a in $allAdapters) { Write-Host "Adapter: $($a.NetConnectionID) MAC: $($a.MACAddress)" }
    $mac = '#{mac_windows}'
    $adapter = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.MACAddress -eq $mac }
    if ($adapter -eq $null) { Write-Host "No adapter found with MAC #{mac_windows}, skipping"; exit 0 }
    $name = $adapter.NetConnectionID
    Write-Host "Scheduling $name to be configured with #{ip} on next boot (Win7)"
    $command = "netsh interface ip set address name=`"$name`" static #{ip} #{netmask}"
    New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' -Name "SetStaticIP_#{nic_index}" -Value $command -PropertyType String -Force
  PS1
        end



        def windows_ip_script_server(nic_index, ip, netmask, mac)
          mac_windows = mac.upcase
          <<~PS1
    $allAdapters = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.MACAddress -ne $null }
    foreach ($a in $allAdapters) { Write-Host "Adapter: $($a.NetConnectionID) MAC: $($a.MACAddress)" }
    $mac = '#{mac_windows}'
    $adapter = Get-WmiObject Win32_NetworkAdapter | Where-Object { $_.MACAddress -eq $mac }
    if ($adapter -eq $null) { Write-Host "No adapter found with MAC #{mac_windows}, skipping"; exit 0 }
    $name = $adapter.NetConnectionID
    Write-Host "Scheduling $name to be configured with #{ip} on next boot (Server 2016+)"
    New-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' -Name "SetStaticIP_#{nic_index}" -Value "netsh interface ip set address name=`"$name`" static #{ip} #{netmask}" -PropertyType String -Force
    Write-Host "RunOnce value stored"
  PS1
        end



        # def windows_ip_script(nic_index, ip, netmask)
          # cidr = cidr_from_netmask(netmask)
          # <<~PS1
          #   $adapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -notlike '*Loopback*' } | Sort-Object -Property InterfaceIndex
          #   if ($adapters.Count -le #{nic_index}) { Write-Error "No NIC at index #{nic_index}"; exit 1 }
          #   $adapter = $adapters[#{nic_index}]
          #   Write-Host "Configuring $($adapter.Name) with #{ip}"
          #   $adapter | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
          #   New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress "#{ip}" -PrefixLength #{cidr} -ErrorAction Stop
          #   Set-NetIPInterface -InterfaceAlias $adapter.Name -Dhcp Disabled
          # PS1
        # end

        def cidr_from_netmask(netmask)
          netmask.split('.').map { |o| o.to_i.to_s(2).count('1') }.sum
        end

      end

    end
  end
end