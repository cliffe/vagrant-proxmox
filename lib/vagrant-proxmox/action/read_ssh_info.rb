# require 'irb'

module VagrantPlugins
	module Proxmox
		module Action

			# This action stores the ssh information in env[:machine_ssh_info]
			class ReadSSHInfo < ProxmoxAction

				def initialize app, env
					@app = app
					@logger = Log4r::Logger.new 'vagrant_proxmox::action::read_ssh_info'
				end

				def call env
					# here, we have to determine how to connect to new vm
					env[:ui].info I18n.t('vagrant_proxmox.read_ssh_info')
          # binding.irb
          env[:ui].detail "Waiting for IP address:"
          begin
            retries ||= 0
            sleep 5 if retries > 0
            ip_address = get_machine_ip_address(env)
            raise 'IP not found' unless ip_address
            env[:ui].detail "Using #{ip_address}:#{env[:machine].config.ssh.guest_port} to connect to VM"

            env[:machine_ssh_info] = {
              :host             => ip_address,
              :port             => env[:machine].config.ssh.guest_port,
              :username         => env[:machine].config.ssh.username,
              :private_key_path => env[:machine].config.ssh.private_key_path,
              :forward_agent    => env[:machine].config.ssh.forward_agent,
              :forward_x11      => env[:machine].config.ssh.forward_x11,
            }
            env[:ui].detail "Found machine_ssh_info #{env[:machine_ssh_info]}"
          rescue => e
            retry if (retries += 1) < 60 # wait up to 5 mins
            raise Errors::CommunicationError,
            error_msg: "ReadSSHInfo: #{e.message}"
            false
          end
          next_action env

				end

			end

		end
	end
end
