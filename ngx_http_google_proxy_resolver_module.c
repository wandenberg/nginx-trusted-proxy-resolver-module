#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t    ngx_http_google_proxy_resolver_pre_config(ngx_conf_t *cf);
ngx_int_t    ngx_http_google_proxy_resolver_init_worker(ngx_cycle_t *cycle);
ngx_int_t    ngx_http_google_proxy_resolver_realip_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_flag_t   ngx_http_google_proxy_resolver_is_accessing_through_google_proxy(ngx_http_request_t *r);
ngx_str_t   *ngx_http_google_proxy_resolver_create_str(ngx_pool_t *pool, uint len);
ngx_str_t   *ngx_http_google_proxy_resolver_get_header(ngx_http_request_t *r, const ngx_str_t *header_name);
ngx_str_t   *ngx_http_google_proxy_resolver_get_hostname(struct sockaddr *addr, ngx_pool_t *pool);
ngx_str_t   *ngx_http_google_proxy_resolver_get_host_ip(ngx_str_t *hostname, struct sockaddr *addr, ngx_pool_t *pool);
void         ngx_http_google_proxy_resolver_get_last_x_forwarded_for_valid_ip(ngx_http_request_t *r, ngx_str_t *ip);


const ngx_str_t  HEADER_VIA = ngx_string("Via");
const ngx_str_t  GOOGLE_COMPRESSION_PROXY = ngx_string("Chrome Compression Proxy");
const ngx_str_t  GOOGLE_PROXY_DOMAIN_PATTERN = ngx_string("^google-proxy-[0-9\\-]*\\.google\\.com$");

ngx_regex_t *google_proxy_domain_regexp = NULL;

static ngx_http_variable_t  ngx_http_google_proxy_resolver_vars[] = {
    { ngx_string("google_proxy_resolver_realip"),
      NULL,
      ngx_http_google_proxy_resolver_realip_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t ngx_http_google_proxy_resolver_commands[] = {
    ngx_null_command
};


static ngx_http_module_t ngx_http_google_proxy_resolver_module_ctx = {
    ngx_http_google_proxy_resolver_pre_config, /* preconfiguration */
    NULL,                                      /* postconfiguration */

    NULL,                                      /* create main configuration */
    NULL,                                      /* init main configuration */

    NULL,                                      /* create server configuration */
    NULL,                                      /* merge server configuration */

    NULL,                                      /* create location configuration */
    NULL                                       /* merge location configuration */
};


ngx_module_t ngx_http_google_proxy_resolver_module = {
    NGX_MODULE_V1,
    &ngx_http_google_proxy_resolver_module_ctx, /* module context */
    ngx_http_google_proxy_resolver_commands,    /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    ngx_http_google_proxy_resolver_init_worker, /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_google_proxy_resolver_pre_config(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_google_proxy_resolver_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_google_proxy_resolver_init_worker(ngx_cycle_t *cycle)
{
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t *rc = NULL;

    if ((rc = ngx_pcalloc(cycle->pool, sizeof(ngx_regex_compile_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_google_proxy_resolver_module: unable to allocate memory to compile google proxy domain pattern");
        return NGX_ERROR;
    }

    rc->pattern = GOOGLE_PROXY_DOMAIN_PATTERN;
    rc->pool = cycle->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_google_proxy_resolver_module: unable to compile google proxy domain pattern %V", &GOOGLE_PROXY_DOMAIN_PATTERN);
        return NGX_ERROR;
    }

    google_proxy_domain_regexp = rc->regex;

    return NGX_OK;
}


ngx_int_t
ngx_http_google_proxy_resolver_realip_variable(ngx_http_request_t *r, ngx_http_variable_value_t *var, uintptr_t data)
{
    ngx_str_t          ip = ngx_null_string;

    if (var->len > 0) {
        return NGX_OK;
    }

#if nginx_version < 1003014
    if ((r->headers_in.x_forwarded_for != NULL) && ngx_http_google_proxy_resolver_is_accessing_through_google_proxy(r)) {
#else
    if ((r->headers_in.x_forwarded_for.elts != NULL) && ngx_http_google_proxy_resolver_is_accessing_through_google_proxy(r)) {
#endif
        ngx_http_google_proxy_resolver_get_last_x_forwarded_for_valid_ip(r, &ip);

        if (ip.len == 0) {
            return NGX_ERROR;
        }

        var->len = ip.len;
        var->data = ip.data;
    } else {
        var->len = r->connection->addr_text.len;
        var->data = r->connection->addr_text.data;
    }

    return NGX_OK;
}


ngx_flag_t
ngx_http_google_proxy_resolver_is_accessing_through_google_proxy(ngx_http_request_t *r)
{
    ngx_str_t          *via_header, *hostname, *ip;

    if ((via_header = ngx_http_google_proxy_resolver_get_header(r, &HEADER_VIA)) != NULL) {
        if (ngx_strlcasestrn(via_header->data, via_header->data + via_header->len, GOOGLE_COMPRESSION_PROXY.data, GOOGLE_COMPRESSION_PROXY.len - 1) != NULL) {
            if ((hostname = ngx_http_google_proxy_resolver_get_hostname(r->connection->sockaddr, r->pool)) != NULL) {
                if (ngx_regex_exec(google_proxy_domain_regexp, hostname, NULL, 0) != NGX_REGEX_NO_MATCHED) {
                    if ((ip = ngx_http_google_proxy_resolver_get_host_ip(hostname, r->connection->sockaddr, r->pool)) != NULL) {
                        if (ngx_strncmp(ip->data, r->connection->addr_text.data, r->connection->addr_text.len) == 0) {
                            return 1;
                        }
                    }
                }
            }
        }
    }

    return 0;
}


ngx_str_t *
ngx_http_google_proxy_resolver_create_str(ngx_pool_t *pool, uint len)
{
    ngx_str_t *aux = (ngx_str_t *) ngx_pcalloc(pool, sizeof(ngx_str_t) + len + 1);

    if (aux != NULL) {
        aux->data = (u_char *) (aux + 1);
        aux->len = len;
        ngx_memset(aux->data, '\0', len + 1);
    }

    return aux;
}


ngx_str_t *
ngx_http_google_proxy_resolver_get_header(ngx_http_request_t *r, const ngx_str_t *header_name)
{
    ngx_table_elt_t             *h;
    ngx_list_part_t             *part;
    ngx_uint_t                   i;
    ngx_str_t                   *aux = NULL;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if ((h[i].key.len == header_name->len) && (ngx_strncasecmp(h[i].key.data, header_name->data, header_name->len) == 0)) {
            if ((aux = (ngx_str_t *) ngx_pcalloc(r->pool, sizeof(ngx_str_t))) != NULL) {
                aux->len = h[i].value.len;
                aux->data = h[i].value.data;
            }
            break;
        }
    }

    return aux;
}


ngx_str_t *
ngx_http_google_proxy_resolver_get_hostname(struct sockaddr *addr, ngx_pool_t *pool)
{
    char                hostname_buf[NI_MAXHOST];
    ngx_str_t          *hostname = NULL;
    socklen_t           len = (addr->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    if (getnameinfo(addr, len, hostname_buf, NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0) {
        if ((hostname = ngx_http_google_proxy_resolver_create_str(pool, ngx_strlen(hostname_buf))) != NULL) {
            ngx_memcpy(hostname->data, hostname_buf, hostname->len);
        }
    }

    return hostname;
}


ngx_str_t *
ngx_http_google_proxy_resolver_get_host_ip(ngx_str_t *hostname, struct sockaddr *addr, ngx_pool_t *pool)
{
    struct hostent     *host;
    char                host_ip[INET_ADDRSTRLEN];
    ngx_str_t          *ip = NULL;

    if ((host = gethostbyname2((char *) hostname->data, addr->sa_family)) != NULL) {
        if (inet_ntop(addr->sa_family, host->h_addr_list[0], host_ip, INET_ADDRSTRLEN) != NULL) {
            if ((ip = ngx_http_google_proxy_resolver_create_str(pool, ngx_strlen(host_ip))) != NULL) {
                ngx_memcpy(ip->data, host_ip, ip->len);
            }
        }
    }

    return ip;
}


void
ngx_http_google_proxy_resolver_get_last_x_forwarded_for_valid_ip(ngx_http_request_t *r, ngx_str_t *ip)
{
    u_char           *p, *xff;
    size_t            xfflen;

#if nginx_version < 1003014
    xff = r->headers_in.x_forwarded_for->value.data;
    xfflen = r->headers_in.x_forwarded_for->value.len;
#else
    ngx_table_elt_t  **h = r->headers_in.x_forwarded_for.elts;
    xff = h[r->headers_in.x_forwarded_for.nelts - 1]->value.data;
    xfflen = h[r->headers_in.x_forwarded_for.nelts - 1]->value.len;
#endif

    for (p = xff + xfflen - 1; p > xff; p--, xfflen--) {
        if (*p != ' ' && *p != ',') {
            break;
        }
    }

    for ( /* void */ ; p > xff; p--) {
        if (*p == ' ' || *p == ',') {
            p++;
            break;
        }
    }

    ip->len = xfflen - (p - xff);
    ip->data = p;
}
