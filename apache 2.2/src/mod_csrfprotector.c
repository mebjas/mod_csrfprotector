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
 * @param: length, int
 * @return: token, string
 */
static char* generateToken(request_rec *r, int length)
{
    const char* strinset = "ABCDEFGHIJKLMNOPQRSTWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    /**
     * @procedure: Generate a PRNG of length 128, retrun substr of length -- length
     */
    char *token;
    token = apr_pcalloc(r->pool, sizeof(char) * 128);

    //substring to be returned to the calling function
    char tok[length];
    int i;

    for (i = 0; i < 128; i++) {
        //Generate a random no between 0 and 124
        int rno = rand() % 123 + 1;
        if (rno < 62) {
            token[i] = strinset[rno];
        } else {
            token[i] = strinset[rno - 62];
        }
    }

    strncpy(tok, &token[0], length);
    tok[length] = '\0';

    return tok;
}

/**
 * Function to get value of a certain query key, in Query String
 * @param: 
 * @retrun: 
 */
static char* getKeyValue(request_rec *r, char *key)
{

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
            if ( !strcmp(formData[i].key, "csrfp_token") ) {
                ++flag;
                // #todo: Now match this token with the cookie value
            }
        }

        if (!flag) return 0;
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

    //ap_rprintf(r, "%s", r->args);

    char * tok = generateToken(r, 10);
    //ap_rprintf(r, "token = %s", tok);


    /*temp code to print out all headers*/
    const apr_array_header_t    *fields;
    int                         i;
    apr_table_entry_t           *e = 0;
    /*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/

    fields = apr_table_elts(r->headers_in);
    e = (apr_table_entry_t *) fields->elts;
    for(i = 0; i < fields->nelts; i++) {
        ap_rprintf(r, "%s: %s\n", e[i].key, e[i].val);
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
