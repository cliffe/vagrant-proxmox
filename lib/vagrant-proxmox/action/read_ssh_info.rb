# require 'irb'
require 'socket'

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

            # Check if SSH port is open before continuing
            ssh_port_open = false
            max_retries = 60
            retries = 0
            while !ssh_port_open && retries < max_retries
              begin
                socket = Socket.new(Socket::AF_INET, Socket::SOCK_STREAM, 0)
                sockaddr = Socket.pack_sockaddr_in(env[:machine].config.ssh.guest_port, ip_address)
                if socket.connect(sockaddr)
                  ssh_port_open = true
                  socket.close
                end
                retries += 1
                sleep 5 if retries < max_retries
              rescue StandardError => e
                env[:ui].error "Error while checking SSH port: #{e.message}"
                raise Errors::CommunicationError, error_msg: "SSH port check failed"
              end
            end

            unless ssh_port_open
              env[:ui].error "SSH port is not open on #{ip_address}:#{env[:machine].config.ssh.guest_port}"
              raise Errors::CommunicationError, error_msg: "SSH port is not open"
            end


            sleep 3
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
