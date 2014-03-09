#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_http_variables.h>
#include <sys/types.h>

#if (NGX_FREEBSD)
#error FreeBSD is not supported yet, sorry.
#elif (NGX_LINUX)
#include <ossp/uuid.h>
#elif (NGX_SOLARIS)
#error Solaris is not supported yet, sorry.
#elif (NGX_DARWIN)
#include <uuid/uuid.h>
#endif

// TODO:
//
// * make the name of the variable configurable

static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len);

// Convert an array of 8 bytes into a 64 bit unsigned int
u_int64_t bits2uint64(u_char* const bits) {
   return ((u_int64_t)bits[0] << 56)
        | ((u_int64_t)bits[1] << 48)
        | ((u_int64_t)bits[2] << 40)
        | ((u_int64_t)bits[3] << 32)
        | ((u_int64_t)bits[4] << 24)
        | ((u_int64_t)bits[5] << 16)
        | ((u_int64_t)bits[6] <<  8)
        |  (u_int64_t)bits[7];
}

// Format the UUID as 22 characters in base58
void uuid_fmt22(uuid_t* u, u_char* buf) {
    static const int len = 11;
    static const int base = 58;
    static const char digits[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHJKLMNOPQRSTUVWXYZ"
        "2345679"; // Excludes I180

    int i,j;

    // for hi/lo of 128 bits
    for (i=0; i < 2; i++) {
        u_int64_t block = bits2uint64((u_char*)u+(i*8));

        for (j=0; j < len; j++) {
            buf[j+(i*len)] = digits[block % base];
            block = block / base;
        }
    }
}

static ngx_str_t  ngx_x_rid_header_name = ngx_string("x-request-id");

ngx_int_t ngx_x_rid_header_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
  u_char            *p         = NULL;
  ngx_table_elt_t   *header;
  ngx_str_t          hv;
  size_t             hlen      = 22;

  header = search_headers_in(r, ngx_x_rid_header_name.data, ngx_x_rid_header_name.len);

  if (header != NULL) {
      hv = header->value;

      if (hv.len >= 20 && hv.len <= 50) {
          // Reuse existing header
          hlen = hv.len;
          p = hv.data;
      }
  }

  if (p == NULL) {
      // Prepare 22 bytes to store the base58 string
      p = ngx_pnalloc(r->pool, 22);
      if (p == NULL) {
          return NGX_ERROR;
      }

#if (NGX_FREEBSD)
#error FreeBSD is not supported yet, sorry.
#elif (NGX_LINUX)
      uuid_t* uuid;

      // return of uuid_s_ok = 0
      if ( uuid_create(&uuid) ) {
        return -1;
      }
      if ( uuid_make(uuid, UUID_MAKE_V4) ) {
        uuid_destroy(uuid);
        return -1;
      }

      // at this point we have 16 bytes in "uuid", ready for conversion
      uuid_fmt22(uuid, p);
      uuid_destroy(uuid);
#elif (NGX_SOLARIS)
#error Solaris is not supported yet, sorry.
#elif (NGX_DARWIN)
      uuid_t uuid;
      uuid_generate(uuid);
      uuid_fmt22(uuid, p);
#endif
  }

  v->len = hlen;
  v->valid = 1;
  v->no_cacheable = 0;
  v->not_found = 0;
  v->data = p;

  return NGX_OK;
}

static ngx_str_t  ngx_x_rid_header_variable_name = ngx_string("request_id");

static ngx_int_t ngx_x_rid_header_add_variables(ngx_conf_t *cf)
{
  ngx_http_variable_t* var = ngx_http_add_variable(cf, &ngx_x_rid_header_variable_name, NGX_HTTP_VAR_NOHASH);
  if (var == NULL) {
      return NGX_ERROR;
  }
  var->get_handler = ngx_x_rid_header_get_variable;
  return NGX_OK;
}

static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len)
{
	ngx_list_part_t            *part;
	ngx_table_elt_t            *h;
	ngx_uint_t                  i;

	part = &r->headers_in.headers.part;
	h = part->elts;

	// Headers array may consist of more than one part, so loop throgh all of them
	for (i = 0; ; i++) {
		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			h = part->elts;
			i = 0;
		}

		// Compare names case insensitively
		if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
			continue;
		}

		// Found it
		return &h[i];
	}

	// no header was found
	return NULL;
}

static ngx_http_module_t  ngx_x_rid_header_module_ctx = {
  ngx_x_rid_header_add_variables,     /* preconfiguration */
  NULL,                               /* postconfiguration */

  NULL,        /* create main configuration */
  NULL,        /* init main configuration */

  NULL,        /* create server configuration */
  NULL,        /* merge server configuration */

  NULL,        /* create location configuration */
  NULL         /* merge location configuration */
};

static ngx_command_t  ngx_x_rid_header_module_commands[] = {
  ngx_null_command
};

ngx_module_t  ngx_x_rid_header_module = {
  NGX_MODULE_V1,
  &ngx_x_rid_header_module_ctx,      /* module context */
  ngx_x_rid_header_module_commands,  /* module directives */
  NGX_HTTP_MODULE,                   /* module type */
  NULL,                              /* init master */
  NULL,                              /* init module */
  NULL,                              /* init process */
  NULL,                              /* init thread */
  NULL,                              /* exit thread */
  NULL,                              /* exit process */
  NULL,                              /* exit master */
  NGX_MODULE_V1_PADDING
};

