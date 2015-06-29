#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t    ngx_http_trusted_proxy_resolver_pre_config(ngx_conf_t *cf);
ngx_int_t    ngx_http_trusted_proxy_resolver_post_config(ngx_conf_t *cf);
void        *ngx_http_trusted_proxy_resolver_create_loc_conf(ngx_conf_t *cf);
char        *ngx_http_trusted_proxy_resolver_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
ngx_int_t    ngx_http_trusted_proxy_resolver_init_worker(ngx_cycle_t *cycle);
ngx_int_t    ngx_http_trusted_proxy_resolver_realip_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
ngx_int_t    ngx_http_trusted_proxy_resolver_handler(ngx_http_request_t *r);
ngx_flag_t   ngx_http_trusted_proxy_resolver_is_accessing_through_google_proxy(ngx_http_request_t *r);
ngx_str_t   *ngx_http_trusted_proxy_resolver_create_str(ngx_pool_t *pool, uint len);
ngx_str_t   *ngx_http_trusted_proxy_resolver_get_hostname(struct sockaddr *addr, ngx_pool_t *pool);
ngx_str_t   *ngx_http_trusted_proxy_resolver_get_host_ip(ngx_str_t *hostname, struct sockaddr *addr, ngx_pool_t *pool);
void         ngx_http_trusted_proxy_resolver_get_last_x_forwarded_for_valid_ip(ngx_http_request_t *r, ngx_str_t *ip);
ngx_int_t    ngx_http_trusted_proxy_resolver_set_addr(ngx_http_request_t *r, ngx_addr_t *addr);
void         ngx_http_trusted_proxy_resolver_cleanup(void *data);


const ngx_str_t  GOOGLE_PROXY_DOMAIN_PATTERN = ngx_string("^google-proxy-[0-9\\-]*\\.google\\.com$");

ngx_regex_t *google_proxy_domain_regexp = NULL;

typedef struct {
    ngx_flag_t                enabled;
    ngx_http_complex_value_t *address;
} ngx_http_trusted_proxy_resolver_loc_conf_t;

typedef struct {
    ngx_connection_t  *connection;
    struct sockaddr   *sockaddr;
    socklen_t          socklen;
    ngx_str_t          addr_text;
} ngx_http_trusted_proxy_resolver_ctx_t;

static ngx_http_variable_t  ngx_http_trusted_proxy_resolver_vars[] = {
    { ngx_string("trusted_proxy_resolver_realip"),
      NULL,
      ngx_http_trusted_proxy_resolver_realip_variable,
      0, NGX_HTTP_VAR_NOCACHEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_command_t ngx_http_trusted_proxy_resolver_commands[] = {
    { ngx_string("trusted_proxy_resolver_to_real_ip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_trusted_proxy_resolver_loc_conf_t, enabled),
      NULL },

    { ngx_string("trusted_proxy_resolver_address"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_set_complex_value_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_trusted_proxy_resolver_loc_conf_t, address),
      NULL },
    ngx_null_command
};


static ngx_http_module_t ngx_http_trusted_proxy_resolver_module_ctx = {
    ngx_http_trusted_proxy_resolver_pre_config,         /* preconfiguration */
    ngx_http_trusted_proxy_resolver_post_config,        /* postconfiguration */

    NULL,                                              /* create main configuration */
    NULL,                                              /* init main configuration */

    NULL,                                              /* create server configuration */
    NULL,                                              /* merge server configuration */

    ngx_http_trusted_proxy_resolver_create_loc_conf,    /* create location configuration */
    ngx_http_trusted_proxy_resolver_merge_loc_conf      /* merge location configuration */
};


ngx_module_t ngx_http_trusted_proxy_resolver_module = {
    NGX_MODULE_V1,
    &ngx_http_trusted_proxy_resolver_module_ctx, /* module context */
    ngx_http_trusted_proxy_resolver_commands,    /* module directives */
    NGX_HTTP_MODULE,                            /* module type */
    NULL,                                       /* init master */
    NULL,                                       /* init module */
    ngx_http_trusted_proxy_resolver_init_worker, /* init process */
    NULL,                                       /* init thread */
    NULL,                                       /* exit thread */
    NULL,                                       /* exit process */
    NULL,                                       /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_http_trusted_proxy_resolver_pre_config(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_trusted_proxy_resolver_vars; v->name.len; v++) {
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
ngx_http_trusted_proxy_resolver_post_config(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_trusted_proxy_resolver_handler;

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_trusted_proxy_resolver_handler;

    return NGX_OK;
}


void *
ngx_http_trusted_proxy_resolver_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_trusted_proxy_resolver_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_trusted_proxy_resolver_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->address = NULL;

    return conf;
}


char *
ngx_http_trusted_proxy_resolver_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_trusted_proxy_resolver_loc_conf_t  *prev = parent;
    ngx_http_trusted_proxy_resolver_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);

    if (conf->address == NULL) {
        conf->address = prev->address;
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_trusted_proxy_resolver_init_worker(ngx_cycle_t *cycle)
{
    u_char errstr[NGX_MAX_CONF_ERRSTR];
    ngx_regex_compile_t *rc = NULL;

    if ((rc = ngx_pcalloc(cycle->pool, sizeof(ngx_regex_compile_t))) == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_trusted_proxy_resolver_module: unable to allocate memory to compile google proxy domain pattern");
        return NGX_ERROR;
    }

    rc->pattern = GOOGLE_PROXY_DOMAIN_PATTERN;
    rc->pool = cycle->pool;
    rc->err.len = NGX_MAX_CONF_ERRSTR;
    rc->err.data = errstr;

    if (ngx_regex_compile(rc) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "ngx_http_trusted_proxy_resolver_module: unable to compile google proxy domain pattern %V", &GOOGLE_PROXY_DOMAIN_PATTERN);
        return NGX_ERROR;
    }

    google_proxy_domain_regexp = rc->regex;

    return NGX_OK;
}


ngx_int_t
ngx_http_trusted_proxy_resolver_realip_variable(ngx_http_request_t *r, ngx_http_variable_value_t *var, uintptr_t data)
{
    ngx_http_trusted_proxy_resolver_loc_conf_t  *gprlc = ngx_http_get_module_loc_conf(r, ngx_http_trusted_proxy_resolver_module);
    ngx_str_t                                    ip = ngx_null_string;
    ngx_str_t                                    vv_address = ngx_null_string;
    ngx_addr_t                                   address;
    ngx_str_t                                   *addr_text = &r->connection->addr_text;

    if (var->len > 0) {
        return NGX_OK;
    }

    if (gprlc->address) {
        ngx_http_complex_value(r, gprlc->address, &vv_address);
        if (vv_address.len > 0) {
            if (ngx_parse_addr(r->pool, &address, vv_address.data, vv_address.len) == NGX_OK) {
                addr_text = &vv_address;
            }
        }
    }

    if (gprlc->enabled && (r->headers_in.x_forwarded_for.elts != NULL) && ngx_http_trusted_proxy_resolver_is_accessing_through_google_proxy(r)) {
        ngx_http_trusted_proxy_resolver_get_last_x_forwarded_for_valid_ip(r, &ip);

        if (ip.len == 0) {
            return NGX_ERROR;
        }

        var->len = ip.len;
        var->data = ip.data;
    } else {
        var->len = addr_text->len;
        var->data = addr_text->data;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_trusted_proxy_resolver_handler(ngx_http_request_t *r)
{
    ngx_http_trusted_proxy_resolver_loc_conf_t  *gprlc = ngx_http_get_module_loc_conf(r, ngx_http_trusted_proxy_resolver_module);
    ngx_http_trusted_proxy_resolver_ctx_t       *ctx = ngx_http_get_module_ctx(r, ngx_http_trusted_proxy_resolver_module);
    ngx_str_t                                   ip = ngx_null_string;
    ngx_addr_t                                  addr;

    if ((!gprlc->enabled) || (ctx != NULL)) {
        return NGX_DECLINED;
    }

    if ((r->headers_in.x_forwarded_for.elts != NULL) && ngx_http_trusted_proxy_resolver_is_accessing_through_google_proxy(r)) {

        ngx_http_trusted_proxy_resolver_get_last_x_forwarded_for_valid_ip(r, &ip);

        if (ip.len > 0) {
            addr.sockaddr = r->connection->sockaddr;
            addr.socklen = r->connection->socklen;
            if (ngx_parse_addr(r->pool, &addr, ip.data, ip.len) == NGX_OK) {
                return ngx_http_trusted_proxy_resolver_set_addr(r, &addr);
            }
        }
    }

    return NGX_DECLINED;
}


ngx_flag_t
ngx_http_trusted_proxy_resolver_is_accessing_through_google_proxy(ngx_http_request_t *r)
{
    ngx_http_trusted_proxy_resolver_loc_conf_t  *gprlc = ngx_http_get_module_loc_conf(r, ngx_http_trusted_proxy_resolver_module);
    ngx_str_t                                   *hostname, *ip;
    ngx_str_t                                    vv_address = ngx_null_string;
    struct sockaddr                             *sockaddr = r->connection->sockaddr;
    ngx_addr_t                                   address;
    ngx_str_t                                   *addr_text = &r->connection->addr_text;

    if (gprlc->address) {
        ngx_http_complex_value(r, gprlc->address, &vv_address);
        if (vv_address.len > 0) {
            if (ngx_parse_addr(r->pool, &address, vv_address.data, vv_address.len) == NGX_OK) {
                sockaddr = address.sockaddr;
                addr_text = &vv_address;
            }
        }
    }

    if ((hostname = ngx_http_trusted_proxy_resolver_get_hostname(sockaddr, r->pool)) != NULL) {
        if (ngx_regex_exec(google_proxy_domain_regexp, hostname, NULL, 0) != NGX_REGEX_NO_MATCHED) {
            if ((ip = ngx_http_trusted_proxy_resolver_get_host_ip(hostname, sockaddr, r->pool)) != NULL) {
                if (ngx_strncmp(ip->data, addr_text->data, addr_text->len) == 0) {
                    return 1;
                }
            }
        }
    }

    return 0;
}


ngx_str_t *
ngx_http_trusted_proxy_resolver_create_str(ngx_pool_t *pool, uint len)
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
ngx_http_trusted_proxy_resolver_get_hostname(struct sockaddr *addr, ngx_pool_t *pool)
{
    char                hostname_buf[NI_MAXHOST];
    ngx_str_t          *hostname = NULL;
    socklen_t           len = (addr->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);

    if (getnameinfo(addr, len, hostname_buf, NI_MAXHOST, NULL, 0, NI_NAMEREQD) == 0) {
        if ((hostname = ngx_http_trusted_proxy_resolver_create_str(pool, ngx_strlen(hostname_buf))) != NULL) {
            ngx_memcpy(hostname->data, hostname_buf, hostname->len);
        }
    }

    return hostname;
}


ngx_str_t *
ngx_http_trusted_proxy_resolver_get_host_ip(ngx_str_t *hostname, struct sockaddr *addr, ngx_pool_t *pool)
{
    struct hostent     *host;
    char                host_ip[INET6_ADDRSTRLEN];
    ngx_str_t          *ip = NULL;

    if ((host = gethostbyname2((char *) hostname->data, addr->sa_family)) != NULL) {
        if (inet_ntop(addr->sa_family, host->h_addr_list[0], host_ip, INET6_ADDRSTRLEN) != NULL) {
            if ((ip = ngx_http_trusted_proxy_resolver_create_str(pool, ngx_strlen(host_ip))) != NULL) {
                ngx_memcpy(ip->data, host_ip, ip->len);
            }
        }
    }

    return ip;
}


void
ngx_http_trusted_proxy_resolver_get_last_x_forwarded_for_valid_ip(ngx_http_request_t *r, ngx_str_t *ip)
{
    u_char           *p, *xff;
    size_t            xfflen;

    ngx_table_elt_t  **h = r->headers_in.x_forwarded_for.elts;
    xff = h[r->headers_in.x_forwarded_for.nelts - 1]->value.data;
    xfflen = h[r->headers_in.x_forwarded_for.nelts - 1]->value.len;

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


ngx_int_t
ngx_http_trusted_proxy_resolver_set_addr(ngx_http_request_t *r, ngx_addr_t *addr)
{
    size_t                  len;
    u_char                 *p;
    u_char                  text[NGX_SOCKADDR_STRLEN];
    ngx_connection_t       *c;
    ngx_pool_cleanup_t     *cln;
    ngx_http_trusted_proxy_resolver_ctx_t  *ctx;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_http_trusted_proxy_resolver_ctx_t));
    if (cln == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ctx = cln->data;
    ngx_http_set_ctx(r, ctx, ngx_http_trusted_proxy_resolver_module);

    c = r->connection;

    len = ngx_sock_ntop(addr->sockaddr, addr->socklen, text, NGX_SOCKADDR_STRLEN, 0);

    if (len == 0) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_memcpy(p, text, len);

    cln->handler = ngx_http_trusted_proxy_resolver_cleanup;

    ctx->connection = c;
    ctx->sockaddr = c->sockaddr;
    ctx->socklen = c->socklen;
    ctx->addr_text = c->addr_text;

    c->sockaddr = addr->sockaddr;
    c->socklen = addr->socklen;
    c->addr_text.len = len;
    c->addr_text.data = p;

    return NGX_DECLINED;
}


void
ngx_http_trusted_proxy_resolver_cleanup(void *data)
{
    ngx_http_trusted_proxy_resolver_ctx_t *ctx = data;

    ngx_connection_t  *c;

    c = ctx->connection;

    c->sockaddr = ctx->sockaddr;
    c->socklen = ctx->socklen;
    c->addr_text = ctx->addr_text;
}
