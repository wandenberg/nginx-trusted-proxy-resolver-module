Nginx Trusted Proxy Resolver Module
===================================

A module to replace the remote address by the last IP on X-Forwarded-For header when the request comes from a trusted proxy.

The current version only works with the "Data compression proxy" from Google chrome.

This module is based on Nginx real IP module.

It checks the DNS and reverse DNS to be sure that the proxy really is who it says to be.

_This module is not distributed with the Nginx source. See [the installation instructions](#installation-instructions)._


Configuration
-------------

An example:

```nginx
pid         logs/nginx.pid;
error_log   logs/nginx-main_error.log debug;

# Development Mode
# master_process      off;
# daemon              off;
worker_processes    1;
worker_rlimit_core  500M;
working_directory /tmp;
debug_points abort;

events {
	worker_connections  1024;
	#use                 kqueue; # MacOS
	use                 epoll; # Linux
}

http {
    default_type    application/octet-stream;

    log_format main  '[$time_local] $host "$request" $request_time s '
                     '$status $body_bytes_sent "$http_referer" '
                     '"$http_user_agent" Remote: "$remote_addr" '
                     'RealIP: "$trusted_proxy_resolver_realip"';

    access_log      logs/nginx-http_access.log main;
    error_log       logs/nginx-http_error.log;

    trusted_proxy_resolver_address "$http_x_origin_ip";

    server {
        listen          8080;
        server_name     localhost;

        location / {
            trusted_proxy_resolver_to_real_ip on;
        }
    }
}
```

Variables
---------

* **$trusted_proxy_resolver_realip** - just list the IP considered as remote IP on the connection


Directives
----------

* **trusted_proxy_resolver_to_real_ip** - enable or disable the resolver.
* **trusted_proxy_resolver_address** - could indicate a header or a variable with the IP to be checked as the origin. If it results in an empty value the client IP is used.

Installation instructions
-------------------------

[Download Nginx Stable](http://nginx.org/en/download.html) source and uncompress it (ex.: to ../nginx). You must then run ./configure with --add-module pointing to this project as usual. Something in the lines of:

```bash
$ ./configure \
    --add-module=../nginx-trusted-proxy-resolver-module \
    --prefix=/home/user/dev-workspace/nginx
$ make
$ make install
```

Building dynamically
-------------------------

[Download Nginx Stable](http://nginx.org/en/download.html) source and uncompress it (ex.: to ../nginx). You must then run ./configure with --with-compat and --add-dynamic-module pointing to this project as usual. Something in the lines of:

```bash
$ ./configure \
    --with-compat \
    --add-dynamic-module=../nginx-trusted-proxy-resolver-module
$ make modules
```

Then the file `ngx_http_trusted_proxy_resolver_module.so` will be generated at the `objs` folder inside your nginx source files

Running tests
-------------

This project uses [nginx_test_helper](https://github.com/wandenberg/nginx_test_helper) on the test suite. So, after you've installed the module, you can just download the necessary gems:

```bash
$ cd test
$ bundle install
```

And run rspec pointing to where your Nginx binary is (default: /usr/local/nginx/sbin/nginx):

```bash
$ NGINX_EXEC=../path/to/my/nginx rspec .
```

Changelog
---------

This is still a work in progress. Be the change. And take a look on the Changelog file.
