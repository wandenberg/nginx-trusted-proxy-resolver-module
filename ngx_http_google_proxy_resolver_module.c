#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t    ngx_http_google_proxy_resolver_pre_config(ngx_conf_t *cf);
ngx_int_t    ngx_http_google_proxy_resolver_realip_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);


static ngx_http_variable_t  ngx_http_google_proxy_resolver_vars[] = {
    { ngx_string("google_proxy_resolver_realip"),
      NULL,
      ngx_http_google_proxy_resolver_realip_variable,
      0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, NGX_HTTP_VAR_NOCACHEABLE, 0 }
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
    &ngx_http_google_proxy_resolver_module_ctx,
    ngx_http_google_proxy_resolver_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
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
ngx_http_google_proxy_resolver_realip_variable(ngx_http_request_t *r, ngx_http_variable_value_t *var, uintptr_t data)
{
    if (var->len > 0) {
        return NGX_OK;
    }

    var->len = r->connection->addr_text.len;
    var->data = r->connection->addr_text.data;

    return NGX_OK;
}
