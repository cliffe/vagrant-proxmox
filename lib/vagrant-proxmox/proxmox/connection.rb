require 'vagrant-proxmox/proxmox/errors'
require 'rest-client'
require 'retryable'
require 'required_parameters'
require 'json'
# require 'irb'


module VagrantPlugins
  module Proxmox
    class Connection
      include RequiredParameters

      attr_reader :api_url
      attr_reader :ticket
      attr_reader :csrf_token
      attr_accessor :vm_id_range
      attr_accessor :task_timeout
      attr_accessor :task_status_check_interval
      attr_accessor :imgcopy_timeout
      attr_accessor :vm_info_cache

      def initialize(api_url, opts = {})
        @api_url = api_url
        @vm_id_range = opts[:vm_id_range] || (900..999)
        @task_timeout = opts[:task_timeout] || 600
        @task_status_check_interval = opts[:task_status_check_interval] || 2
        @imgcopy_timeout = opts[:imgcopy_timeout] || 1200
        @vm_info_cache = {}
      end

      def login(username: required('username'), password: required('password'))
        response = post '/access/ticket', username: username, password: password
        @ticket = response[:data][:ticket]
        @csrf_token = response[:data][:CSRFPreventionToken]
      rescue ApiError::ServerError
        raise ApiError::InvalidCredentials
      rescue => x
        raise ApiError::ConnectionError, x.message
      end

      def get_node_list
        nodelist = get '/nodes'
        nodelist[:data].map { |n| n[:node] }
      end

      def get_vm_state(vm_id, node)
        begin
          response = get "/nodes/#{node}/qemu/#{vm_id}/status/current"
          states = { 'running' => :running,
                     'stopped' => :stopped }
          states[response[:data][:status]]
        rescue ApiError::ServerError
          :not_created
        end
      end

      def wait_for_completion(task_response: required('task_response'), timeout_message: required('timeout_message'))

        task_upid = task_response[:data]
        timeout = task_timeout
        task_type = /UPID:.*?:.*?:.*?:.*?:(.*)?:.*?:.*?:/.match(task_upid)[1]
        timeout = imgcopy_timeout if task_type == 'imgcopy' || task_type == 'qmclone'
        begin
          retryable(on: VagrantPlugins::Proxmox::ProxmoxTaskNotFinished,
                    tries: timeout / task_status_check_interval + 1,
                    sleep: task_status_check_interval) do
            exit_status = get_task_exitstatus task_upid
            exit_status.nil? ? raise(VagrantPlugins::Proxmox::ProxmoxTaskNotFinished) : exit_status
          end
        rescue VagrantPlugins::Proxmox::ProxmoxTaskNotFinished
          raise VagrantPlugins::Proxmox::Errors::Timeout, timeout_message
        end
      end

      def delete_vm(vm_id, node)
        response = delete "/nodes/#{node}/qemu/#{vm_id}"
        wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.destroy_vm_timeout'
      end

      def qemu_agent_get_ip(vm_id, node)
        begin
          # binding.irb
          response = get "/nodes/#{node}/qemu/#{vm_id}/agent/network-get-interfaces"
        rescue ApiError::ServerError
          return nil
        rescue RestClient::InternalServerError
          return nil
        rescue VagrantPlugins::Proxmox::ApiError::ServerError
          return nil
        end
        # select the first nic (0 = lo, 1 = first nic)
        response.dig(:data, :result).each do |nic|
          nic.dig(:"ip-addresses").each do |ip_addresses_block|
            # find an IPv4 address and return it
            if ip_addresses_block.dig(:"ip-address-type") == "ipv4"
              ip = ip_addresses_block.dig(:"ip-address")
              return ip if ip != "127.0.0.1"
            end
          end
        end
        nil
      end

      def create_vm(node: required('node'), vm_type: required('node'), params: required('params'))
        response = post "/nodes/#{node}/#{vm_type}", params
        wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.create_vm_timeout'
      end

      def clone_vm(node: required('node'), vm_type: required('node'), params: required('params'))
        vm_id = params[:vmid]
        params.delete(:vmid)
        params.delete(:ostype)
        params.delete(:ide2)
        params.delete(:sata0)
        params.delete(:sockets)
        params.delete(:cores)
        params.delete(:description)
        params.delete(:memory)
        params.delete(:net0)
        retries = 20
        while retries > 0
          response = post "/nodes/#{node}/#{vm_type}/#{vm_id}/clone", params
          wait_response = wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.create_vm_timeout'
          if wait_response == "OK"
            break
          else
            puts "Failed to clone VM. Retrying..."
            retries -= 1
            sleep rand(5..30) # random sleep time
          end
        end
        if retries == 0
          puts "Failed to clone VM after multiple retries."
        end
        wait_response
      end

      def config_clone(node: required('node'), vm_type: required('node'), params: required('params'))
        vm_id = params[:vmid]
        params.delete(:vmid)
        response = post "/nodes/#{node}/#{vm_type}/#{vm_id}/config", params
        wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.create_vm_timeout'
      end

      def get_vm_config(node: required('node'), vm_id: required('node'), vm_type: required('node'))
        response = get "/nodes/#{node}/#{vm_type}/#{vm_id}/config"
        response = response[:data]
        response.empty? ? raise(VagrantPlugins::Proxmox::Errors::VMConfigError) : response
      end

      def start_vm(vm_id, node)
        response = post "/nodes/#{node}/qemu/#{vm_id}/status/start", nil
        wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.start_vm_timeout'
      end

      def stop_vm(vm_id, node)
        response = post "/nodes/#{node}/qemu/#{vm_id}/status/stop", nil
        wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.stop_vm_timeout'
      end

      def shutdown_vm(vm_id, node)
        response = post "/nodes/#{node}/qemu/#{vm_id}/status/shutdown", nil
        wait_for_completion task_response: response, timeout_message: 'vagrant_proxmox.errors.shutdown_vm_timeout'
      end

      # when given a large range we can optimise by simply choosing an id randomly
      # otherwise we list all the possible ids and compare to what's available
      def get_free_vm_id
        if vm_id_range.size > 1000
          # just randomly choose from within the large range
          rand(vm_id_range)
        else
          # to avoid collisions in multi-vm setups
          sleep (rand(1..3) + 0.1 * rand(0..9))
          response = get '/cluster/resources?type=vm'
          allowed_vm_ids = vm_id_range.to_set
          used_vm_ids = response[:data].map { |vm| vm[:vmid] }
          free_vm_ids = (allowed_vm_ids - used_vm_ids).sort
          free_vm_ids.empty? ? raise(VagrantPlugins::Proxmox::Errors::NoVmIdAvailable) : free_vm_ids.first
        end
      end

      def get_qemu_template_id(template)
        response = get '/cluster/resources?type=vm'
        found_ids = response[:data].select { |vm| vm[:type] == 'qemu' }.select { |vm| vm[:template] == 1 }.select { |vm| vm[:name] == template }.map { |vm| vm[:vmid] }
        found_ids.empty? ? raise(VagrantPlugins::Proxmox::Errors::NoTemplateAvailable) : found_ids.first
      end

      def upload_file(file, content_type: required('content_type'), node: required('node'), storage: required('storage'), replace: false)
        delete_file(filename: file, content_type: content_type, node: node, storage: storage) if replace
        unless is_file_in_storage? filename: file, node: node, storage: storage
          res = post "/nodes/#{node}/storage/#{storage}/upload", content: content_type,
                                                                 filename: File.new(file, 'rb'), node: node, storage: storage
          wait_for_completion task_response: res, timeout_message: 'vagrant_proxmox.errors.upload_timeout'
        end
      end

      def delete_file(filename: required('filename'), content_type: required('content_type'), node: required('node'), storage: required('storage'))
        delete "/nodes/#{node}/storage/#{storage}/content/#{content_type}/#{File.basename filename}"
      end

      def list_storage_files(node: required('node'), storage: required('storage'))
        res = get "/nodes/#{node}/storage/#{storage}/content"
        res[:data].map { |e| e[:volid] }
      end

      def get_node_ip(node, interface)
        response = get "/nodes/#{node}/network/#{interface}"
        response[:data][:address]
      rescue ApiError::ServerError
        :not_created
      end

      # This is called every time to retrieve the node and vm_type, hence on large
      # installations this could be a huge amount of data.
      # @vm_info_cache is used to buffer the info we need, but maybe this should be
      # read from the Vagrantfile -- do we need to get this from proxmox?

      private

      def get_vm_info(vm_id)
        # only look up each VM once -- and cache the results
        if @vm_info_cache.key? vm_id
          @vm_info_cache[vm_id]
          # File.write("#{Dir.home}/.vagrant_proxmox_vm_info_cache.json", JSON.dump(@vm_info_cache))
        else
          response = get '/cluster/resources?type=vm'
          @vm_info_cache[vm_id] = response[:data]
            .select { |m| m[:id] =~ /^[a-z]*\/#{vm_id}$/ }
            .map { |m| { id: vm_id, type: /^(.*)\/(.*)$/.match(m[:id])[1], node: m[:node] } }
            .first
          # binding.irb
        end
      end

      private

      def get_task_exitstatus(task_upid)
        node = /UPID:(.*?):/.match(task_upid)[1]
        response = get "/nodes/#{node}/tasks/#{task_upid}/status"
        response[:data][:exitstatus]
      end

      private

      def get(path)
        response = RestClient.get "#{api_url}#{path}", cookies: { PVEAuthCookie: ticket }
        JSON.parse response.to_s, symbolize_names: true
      rescue RestClient::NotImplemented
        raise ApiError::NotImplemented
      rescue RestClient::InternalServerError => x
        raise ApiError::ServerError, "#{x.message} for GET #{api_url}#{path} details: #{response.to_s} - #{x.inspect}"
      rescue RestClient::Unauthorized
        raise ApiError::UnauthorizedError
      rescue => x
        raise ApiError::ConnectionError, x.message
      end

      private

      def delete(path, _params = {})
        response = RestClient.delete "#{api_url}#{path}", headers
        JSON.parse response.to_s, symbolize_names: true
      rescue RestClient::Unauthorized
        raise ApiError::UnauthorizedError
      rescue RestClient::NotImplemented
        raise ApiError::NotImplemented
      rescue RestClient::InternalServerError => x
        raise ApiError::ServerError, "#{x.message} for DELETE #{api_url}#{path}"
      rescue => x
        raise ApiError::ConnectionError, x.message
      end

      private

      def post(path, params = {})
        response = RestClient.post "#{api_url}#{path}", params, headers
        JSON.parse response.to_s, symbolize_names: true
      rescue RestClient::Unauthorized
        raise ApiError::UnauthorizedError
      rescue RestClient::NotImplemented
        raise ApiError::NotImplemented
      rescue RestClient::InternalServerError => x
        raise ApiError::ServerError, "#{x.message} for POST #{api_url}#{path} details: #{response.to_s} - #{x.inspect}"
      rescue => x
        raise ApiError::ConnectionError, x.message
      end

      private

      def headers
        ticket.nil? ? {} : { CSRFPreventionToken: csrf_token, cookies: { PVEAuthCookie: ticket } }
      end

      private

      def is_file_in_storage?(filename: required('filename'), node: required('node'), storage: required('storage'))
        (list_storage_files node: node, storage: storage).find { |f| f =~ /#{File.basename filename}/ }
      end
    end
  end
end
