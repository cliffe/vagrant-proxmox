module VagrantPlugins
  module Proxmox
    module Action

      # This action reads the state of a Proxmox virtual machine and stores it
      # in env[:machine_state_id].
      class SelectNode < ProxmoxAction

        def initialize app, env
          @app = app
          @logger = Log4r::Logger.new 'vagrant_proxmox::action::select_node'
        end

        def call env
          if env[:machine].provider_config.selected_node != Config::UNSET_VALUE
            # optimize by assuming that our congured node is available
            # if env[:proxmox_nodes].include?(env[:machine].provider_config.selected_node)
            #   env[:proxmox_selected_node] = env[:machine].provider_config.selected_node
            # else
            #   raise Errors::InvalidNodeError, node: env[:machine].provider_config.selected_node
            # end
            env[:proxmox_selected_node] = env[:machine].provider_config.selected_node
          else
            env[:proxmox_selected_node] = env[:proxmox_nodes].sample
          end
          next_action env
        end

      end

    end
  end
end
