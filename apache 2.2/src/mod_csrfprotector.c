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

//Definations for functions
static int csrf_handler(request_rec *r);
static void csrfp_register_hooks(apr_pool_t *pool);

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

    ap_rprintf(r, "%s", r->args);

    char * tok = generateToken(r, 10);
    ap_rprintf(r, "token = %s", tok);
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
