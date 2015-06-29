require 'nginx_test_helper'
module NginxConfiguration
  def self.default_configuration
    {
      disable_start_stop_server: false,
      master_process: 'off',
      daemon: 'off',

      address: nil,
      to_real_ip: "on",
    }
  end


  def self.template_configuration
  %(
pid               <%= pid_file %>;
error_log         <%= error_log %> debug;

worker_processes  <%= nginx_workers %>;

events {
  worker_connections  1024;
  use                 <%= (RUBY_PLATFORM =~ /darwin/) ? 'kqueue' : 'epoll' %>;
}

http {
  access_log      <%= access_log %>;

  server {
    listen        <%= nginx_port %>;
    server_name   <%= nginx_host %>;

    <%= write_directive("trusted_proxy_resolver_address", address) %>

    location /resolved {
      <%= write_directive("trusted_proxy_resolver_to_real_ip", to_real_ip) %>
      return 200 "$trusted_proxy_resolver_realip";
    }

    location / {
      <%= write_directive("trusted_proxy_resolver_to_real_ip", to_real_ip) %>
    }
  }
}
  )
  end
end
