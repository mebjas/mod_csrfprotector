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

#define CSRFP_TOKEN "csrfp_token"

//=============================================================
// Definations of all data structures to be used later
//=============================================================

/**
 * structure to store key value pair of POST query
 */
typedef struct {
    const char* key;
    const char* value;
} keyValuePair;

//Definations for functions
static int csrf_handler(request_rec *r);
static void csrfp_register_hooks(apr_pool_t *pool);
static char* generateToken(request_rec *r, int length);
static keyValuePair* readPost(request_rec* r);

/**
 * Function to parse the POST query, and return set of keyValuePair
 * i.e. POST query parameters
 * @param: r, request_rec pointer
 * @return: kvp, keyValuePair
 */
static keyValuePair* readPost(request_rec* r) {
    apr_array_header_t *pairs = NULL;
    apr_off_t len;
    apr_size_t size;
    int res;
    int i = 0;
    char *buffer;
    keyValuePair* kvp;

    /*
    res = ap_parse_form_data(r, NULL, &pairs, -1, HUGE_STRING_LEN);

    // Return NULL if we failed or if there are is no POST data
    if (res != OK || !pairs) return NULL; 
    kvp = apr_pcalloc(r->pool, sizeof(keyValuePair) * (pairs->nelts + 1));

    while (pairs && !apr_is_empty_array(pairs)) {
        ap_form_pair_t *pair = (ap_form_pair_t *) apr_array_pop(pairs);
        apr_brigade_length(pair->value, 1, &len);
        size = (apr_size_t) len;
        buffer = apr_palloc(r->pool, size + 1);
        apr_brigade_flatten(pair->value, buffer, &size);
        buffer[len] = 0;
        kvp[i].key = apr_pstrdup(r->pool, pair->name);
        kvp[i].value = buffer;
        i++;
    }
    */
    return kvp;
}

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

/**
 * Function to validate post token, csrfp_token in POST query parameter
 * @param: r, request_rec pointer
 * @return: int, 0 - for failed validation, 1 - for passed
 */
static int validatePOSTtoken(request_rec *r)
{
    keyValuePair *formData;
    
    formData = readPost(r); //retrieve all key value pair
    if (formData) {
        int i, flag = 0;
        for( i = 0; &formData[i]; i++) {
            if ( !strcmp(formData[i].key, CSRFP_TOKEN) ) {
                ++flag;
                // #todo: Now match this token with the cookie value
                // #todo: Need to obtain alternate method for obtaining POST query string
                //          ealier one works with 2.4.x only
            }
        }

        if (!flag) return 0;
    }
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


    /*temp code to print out all headers*/
    const apr_array_header_t    *fields;
    int                         i;
    apr_table_entry_t           *e = 0;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    fields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) fields->elts;
    for(i = 0; i < fields->nelts; i++) {
        ap_rprintf(r, "%s: %s\n<br>", e[i].key, e[i].val);
    }

    apr_table_t *t = csrf_get_query(r);
    const char *temp = apr_table_get(t, CSRFP_TOKEN);
    ap_rprintf(r, "<br> get data = %s", temp);

    if (validateGETTtoken(r)) {
        ap_rprintf(r, "<br>CSRFP GET VALIDATION PASSED"); 
    } else {
        ap_rprintf(r, "<br>CSRFP GET VALIDATION FAILED");    
    }

    return OK;
}


/**
 * Hook registering function for mod_csrfp
 * @param: pool, apr_pool_t
 */
static void csrfp_register_hooks(apr_pool_t *pool)
{
    // Create a hook in the request handler, so we get called when a request arrives
    ap_hook_handler(csrf_handler, NULL, NULL, APR_HOOK_FIRST);
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
