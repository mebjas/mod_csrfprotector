/**
 * Source code of mod_csrfprotector, Apache Module to mitigarte
 * CSRF vulnerability in web applications
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include <apr_buckets.h>
#include "util_filter.h"

#define CSRFP_TOKEN "csrfp_token"
#define DEFAULT_POST_ENCTYPE "application/x-www-form-urlencoded"

//=============================================================
// Definations of all data structures to be used later
//=============================================================


//Definations for functions
static int csrf_handler(request_rec *r);
static void csrfp_register_hooks(apr_pool_t *pool);
static char* generateToken(request_rec *r, int length);

/**
 * Function to generate a pseudo random no to function as
 * CSRFP_TOKEN
 *
 * @param: length, int
 * @return: token, csrftoken - string
 */
static char* generateToken(request_rec *r, int length)
{
    const char* stringset = "ABCDEFGHIJKLMNOPQRSTWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * @procedure: Generate a PRNG of length 128, retrun substr of length -- length
     */
    char *token = NULL;
    token = apr_pcalloc(r->pool, sizeof(char) * length);
    int i;

    for (i = 0; i < length; i++) {
        //Generate a random no between 0 and 124
        int rno = rand() % 123 + 1;
        if (rno < 62) {
            token[i] = stringset[rno];
        } else {
            token[i] = stringset[rno - 62];
        }
    }

    return token;
}

/**
 * Returns a table containing the query name/value pairs.
 *
 * @param r
 * @return tbl, Table of NULL if no parameter are available
 */
static apr_table_t *csrf_get_query(request_rec *r)
{
    apr_table_t *tbl = NULL;
    const char *args = r->args;

    if(args == NULL) {
        return NULL;
    }

    tbl = apr_table_make(r->pool, 10);
    while(args[0]) {
        char *value = ap_getword(r->pool, &args, '&');
        char *name = ap_getword_nc(r->pool, &value, '=');
        if(name) {
            apr_table_addn(tbl, name, value);   
        }
    }
    return tbl;
}

/**
 * Function to return the token value from cookie
 *
 * @param: r, request_rec
 * @return: CSRFP_TOKEN if exist in cookie, else null
 */
static char* getCookieToken(request_rec *r)
{
    const char *cookie = NULL;
    cookie = apr_table_get(r->headers_in, "Cookie");

    if (cookie == NULL) {
        return NULL;
    }

    char *p = strstr(cookie, CSRFP_TOKEN);
    int totalLen = strlen(p), pos = 0, i;

    for (i = 0; i < totalLen; i++) {
        if (p[i] == ';')
            break;
        ++pos;
    }

    int len = pos - strlen(CSRFP_TOKEN) - 1;
    char *tok = NULL;
    tok = apr_pcalloc(r->pool, sizeof(char)*len);

    //retrieve the token from cookie string
    strncpy(tok, &p[strlen(CSRFP_TOKEN) + 1], len);

    return tok;
}

static int util_read(request_rec *r, const char **rbuf)
{
    int rc;
    if ((rc = ap_setup_client_block(r, REQUEST_CHUNKED_ERROR)) != OK) {
        return rc;
    }
    if (ap_should_client_block(r)) {
        char argsbuffer[HUGE_STRING_LEN];
        int rsize, len_read, rpos=0;
        long length = r->remaining;
        *rbuf = apr_pcalloc(r->pool, length + 1);

        while ((len_read = ap_get_client_block(r, argsbuffer, sizeof(argsbuffer))) > 0) { 
          if ((rpos + len_read) > length) {
            rsize = length - rpos;
          } else {
            rsize = len_read;
          }
          memcpy((char*)*rbuf + rpos, argsbuffer, rsize);
          rpos += rsize;
        }
    }
    return rc;
}
static int read_post(request_rec *r, apr_table_t **tbl)
{
    const char *data;
    const char *key, *val, *type;
    int rc = OK;
    if (r->method_number != M_POST) {
        return rc;
    }
    type = apr_table_get(r->headers_in, "Content-Type");
    if (strcasecmp(type, DEFAULT_POST_ENCTYPE) != 0) {
        return DECLINED;
    }
    if ((rc = util_read(r, &data)) != OK) {
        return rc;
    }

    if (*tbl) {
        apr_table_clear(*tbl);
    } else {
        *tbl = apr_table_make(r->pool, 8);
    }
    while(*data && (val = ap_getword(r->pool, &data, '&'))) {
        key = ap_getword(r->pool, &val, '=');
        ap_unescape_url((char*)key);
        ap_unescape_url((char*)val);
        apr_table_setn(*tbl, key, val);
    }
    return OK;
}
/**
 * Function to validate post token, csrfp_token in POST query parameter
 * @param: r, request_rec pointer
 * @return: int, 0 - for failed validation, 1 - for passed
 */
static int validatePOSTtoken(request_rec *r)
{
    apr_table_t *POST = NULL;
    read_post(r, &POST);

    const char *tokenValue = NULL;
    tokenValue = apr_table_get(POST, CSRFP_TOKEN);

    ap_rprintf(r, "<br> POST TOKEN %s", tokenValue);

    return 0;

}

/**
 * Function to validate GET token, csrfp_token in GET query parameter
 *
 * @param: r, request_rec pointer,
 * @return: int, 0 - for failed validation, 1 - for passed
 */
static int validateGETTtoken(request_rec *r)
{
    //get table of all GET key-value pairs
    apr_table_t *GET = NULL;
    GET = csrf_get_query(r);

    if (!GET) return 0;

    //retrieve our CSRF_token from the table
    const char *tokenValue = NULL;
    tokenValue = apr_table_get(GET, CSRFP_TOKEN);

    if (!tokenValue) return 0;
    else {
        if ( !strcmp(tokenValue, getCookieToken(r) )) return 1;

        //token does not match
        return 0;
    }
}

/**
 * Call back function registered by Hook Registering Function
 * @param: r, request_rec object
 * @return: status code, int
 */
static int csrf_handler(request_rec *r)
{

    // Set the appropriate content type
    ap_set_content_type(r, "text/html");
    

    // If we were reached through a GET or a POST request, be happy, else sad.
    if ( !strcmp(r->method, "POST") ) {
        //need to check configs weather or not a validation is needed POST
    } else if ( !strcmp(r->method, "GET") ) {
        //need to check configs weather or not a validation is needed for GET
    }

    //Codes below are test codes, for fiddling phase

    char * tok = generateToken(r, 20);
    ap_rprintf(r, "Token = %s <br>", tok);

    apr_table_t *t = csrf_get_query(r);
    const char *temp = apr_table_get(t, CSRFP_TOKEN);
    ap_rprintf(r, "<br> CSRFP_TOKEN in GET QUERY = %s, in cookie: %s", temp, getCookieToken(r));

    if (validateGETTtoken(r)) {
        ap_rprintf(r, "<br>CSRFP GET VALIDATION PASSED"); 
    } else {
        ap_rprintf(r, "<br>CSRFP GET VALIDATION FAILED");    
    }

    ap_rprintf(r, "<br> HANDLER: %s <br> ARGS: %s", r->handler, r->args);


    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
    const apr_array_header_t    *fields;
    int                         i;
    apr_table_entry_t           *e = 0;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    fields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) fields->elts;
    for(i = 0; i < fields->nelts; i++) {
        ap_rprintf(r, "<br>%s: %s\n", e[i].key, e[i].val);
    }

    validatePOSTtoken(r);

    return OK;
}


/**
 * Hook registering function for mod_csrfp
 * @param: pool, apr_pool_t
 */
static void csrfp_register_hooks(apr_pool_t *pool)
{
    // Create a hook in the request handler, so we get called when a request arrives
    ap_hook_handler(csrf_handler, NULL, NULL, APR_HOOK_MIDDLE);
}



//===================================================================
// Apache Module Defination
//===================================================================
module AP_MODULE_DECLARE_DATA csrf_protector_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    csrfp_register_hooks   /* Our hook registering function */
};
