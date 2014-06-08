/**
 * Source code of mod_csrfprotector, Apache Module to mitigarte
 * CSRF vulnerability in web applications
 */

#include <stdio.h>
#include "apr_hash.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

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


    // Checking Temp
    ap_rprintf(r, "Method used: %s</br>", r->method);
    ap_rprintf(r, "Current handler: %s</br>", r->handler);
    ap_rprintf(r, "Method used: %s</br>", r->filename);



    // Lastly, if there was a query string, let's print that too!
    if (r->args) {
        ap_rprintf(r, "Your query string was: %s", r->args);
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
    ap_hook_handler(csrf_handler, NULL, NULL, APR_HOOK_LAST);
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
