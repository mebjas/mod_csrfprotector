/**
 * Source code of mod_csrfprotector, Apache Module to mitigarte
 * CSRF vulnerability in web applications
 */

/** standard c libs **/
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/** apache **/
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_filter.h"
#include "ap_regex.h"

/** APR **/
#include "apr_hash.h"
#include "apr_buckets.h"

/** definations **/
#define CSRFP_TOKEN "csrfp_token"
#define CSRFP_URI_MAXLENGTH 200
#define CSRFP_ERROR_MESSAGE_MAXLENGTH 200
#define CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH 400

#define DEFAULT_ACTION 0
#define DEFAULT_TOKEN_LENGTH 15
#define DEFAULT_ERROR_MESSAGE "<h2>ACCESS FORBIDDEN BY OWASP CSRF_PROTECTOR!</h2>"
#define DEFAULT_REDIRECT_URL ""
#define DEFAULT_JS_FILE_PATH "http://localhost/csrfp_js/csrfprotector.js"
#define DEFAULT_DISABLED_JS_MESSSAGE "This site attempts to protect users against" \
" <a href=\"https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29\">" \
" Cross-Site Request Forgeries </a> attacks. In order to do so, you must have JavaScript " \
" enabled in your web browser otherwise this site will fail to work correctly for you. " \
" See details of your web browser for how to enable JavaScript."


/** definations for error codes **/
#define CSRFP_ACTION_FORBIDDEN 0
#define CSRFP_ACTION_STRIP 1
#define CSRFP_ACTION_REDIRECT 2
#define CSRFP_ACTION_MESSAGE 3
#define CSRFP_ACTION_INTERNAL_SERVER_ERROR 4



//=============================================================
// Definations of all data structures to be used later
//=============================================================

typedef struct 
{
    int flag;                       // Flag to check if CSRFP is disabled...
                                    // ... 1 by default
    int action;                     // Action Codes, Default - 0
    char *errorRedirectionUri;      // Uri to redirect in case action == 2
    char *errorCustomMessage;       // Message to show in case action == 3
    char *jsFilePath;               // Absolute path for JS file
    int tokenLength;                // Length of CSRFP_TOKEN, Default 20
    char *disablesJsMessage;        // Message to be shown in <noscript>
    ap_regex_t *verifyGetFor;       // Path pattern for which GET requests...
                                    // ...Need to be validated as well
}csrfp_config;

static csrfp_config *config;

//=============================================================
// Globals
//=============================================================
module AP_MODULE_DECLARE_DATA csrf_protector_module;

//Definations for functions
static int csrf_handler(request_rec *r);
static void csrfp_register_hooks(apr_pool_t *pool);
static char* generateToken(request_rec *r, int length);


//=============================================================
// Functions
//=============================================================



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
    const char* tokenValue = NULL;  //retrieve this value from POST request
    //#todo: Code to retreieve CSRFP_TOKEN from post query string

    if (!tokenValue) return 0;
    else {
        if ( !strcmp(tokenValue, getCookieToken(r) )) return 1;
        //token doesn't match
        return 0;
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
    

    // If request type is POST
    // Need to check configs weather or not a validation is needed POST
    if ( !strcmp(r->method, "POST")) {
        if ( !validatePOSTtoken(r) ) {
            //#todo: perform failed validation action
            ap_rprintf(r, "<br>POST validation failed");
        } else {
            ap_rprintf(r, "<br> POST validation passed");
        }
        ap_rprintf(r, "<br> we have a POST request");

    } else if ( !strcmp(r->method, "GET") ) {
        //need to check configs weather or not a validation is needed for GET
        ap_rprintf(r, "<br> we have a GET request");
    }

    //Codes below are test codes, for fiddling phase

    apr_table_t *t = csrf_get_query(r);
    const char *temp = apr_table_get(t, CSRFP_TOKEN);
    ap_rprintf(r, "<br> CSRFP_TOKEN --GET = %s<br> CSRFP_TOKEN --COOKIE = %s", temp, getCookieToken(r));

    if (validateGETTtoken(r)) {
        ap_rprintf(r, "<br>CSRFP GET VALIDATION PASSED"); 
    } else {
        ap_rprintf(r, "<br>CSRFP GET VALIDATION FAILED");    
    }

    // Code to print the configurations
    ap_rprintf(r, "<br> Size: %ld", sizeof(csrfp_config));
    ap_rprintf(r, "<br> SizeOf jsFilePath: %ld", sizeof(config->jsFilePath));

    ap_rprintf(r, "<br>Flag = %d", config->flag);
    ap_rprintf(r, "<br>action = %d", config->action);
    ap_rprintf(r, "<br>errorRedirectionUri = %s", config->errorRedirectionUri);
    ap_rprintf(r, "<br>errorCustomMessage = %s", config->errorCustomMessage);
    ap_rprintf(r, "<br>jsFilePath = %s", config->jsFilePath);
    ap_rprintf(r, "<br>tokenLength = %d", config->tokenLength);
    ap_rprintf(r, "<br>disablesJsMessage = %s", config->disablesJsMessage);
    //ap_rprintf(r, "<br>verifyGetFor = %s", config->verifyGetFor);


    return OK;
}

/**
 * Handler to allocate memory to config object
 * And allocae default values to variabled
 */
static void *csrfp_srv_config_create(apr_pool_t *p, server_rec *s)
{
    // Registering default configurations
    config = apr_pcalloc(p, sizeof(csrfp_config));
    config->flag = 1;
    config->action = DEFAULT_ACTION;
    config->tokenLength = DEFAULT_TOKEN_LENGTH;

    // Allocates memory, and assign defalut value For jsFilePath
    config->jsFilePath = apr_pcalloc(p, CSRFP_URI_MAXLENGTH);
    strncpy(config->jsFilePath, DEFAULT_JS_FILE_PATH,
            CSRFP_URI_MAXLENGTH);

    // Allocates memory, and assign defalut value For errorRedirectionUri
    config->errorRedirectionUri = apr_pcalloc(p, CSRFP_URI_MAXLENGTH);
    strncpy(config->errorRedirectionUri, DEFAULT_REDIRECT_URL,
            CSRFP_URI_MAXLENGTH);

    // Allocates memory, and assign defalut value For errorCustomMessage
    config->errorCustomMessage = apr_pcalloc(p, CSRFP_ERROR_MESSAGE_MAXLENGTH);
    strncpy(config->errorCustomMessage, DEFAULT_ERROR_MESSAGE,
            CSRFP_ERROR_MESSAGE_MAXLENGTH);

    // Allocates memory, and assign defalut value For disablesJsMessage
    config->disablesJsMessage = apr_pcalloc(p, CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH);
    strncpy(config->disablesJsMessage, DEFAULT_DISABLED_JS_MESSSAGE,
            CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH);
}

/** Configuration handler functions **/

/** csrfEnable **/
const char *csrfp_enable_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(!strcasecmp(arg, "off")) config->flag = 0;
    else config->flag = 1;
    return NULL;
}

/** csrfAction **/
const char *csrfp_action_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(!strcasecmp(arg, "forbidden"))
        config->action = CSRFP_ACTION_FORBIDDEN;
    else if (!strcasecmp(arg, "strip"))
        config->action = CSRFP_ACTION_STRIP;
    else if (!strcasecmp(arg, "redirect"))
        config->action = CSRFP_ACTION_REDIRECT;
    else if (!strcasecmp(arg, "message"))
        config->action = CSRFP_ACTION_MESSAGE;
    else if (!strcasecmp(arg, "internal_server_error"))
        config->action = CSRFP_ACTION_INTERNAL_SERVER_ERROR;
    else config->action = CSRFP_ACTION_FORBIDDEN;       //default

    return NULL;
}

/** errorRedirectionUri **/
const char *csrfp_errorRedirectionUri_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        strncpy(config->errorRedirectionUri, arg,
        CSRFP_URI_MAXLENGTH);
    }
    else config->errorRedirectionUri = NULL;

    return NULL;
}

/** errorCustomMessage **/
const char *csrfp_errorCustomMessage_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        strncpy(config->errorCustomMessage, arg,
        CSRFP_ERROR_MESSAGE_MAXLENGTH);
    }
    else config->errorCustomMessage = NULL;

    return NULL;
}

/** jsFilePath **/
const char *csrfp_jsFilePath_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        strncpy(config->jsFilePath, arg,
            CSRFP_URI_MAXLENGTH);
    }
    //no else as default config shall come to effect

    return NULL;
}

/** tokenLength **/
const char *csrfp_tokenLength_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        int length = atoi(arg);
        if (length) config->tokenLength = length;
    }
    //no else as default config shall come to effect

    return NULL;
}

/** disablesJsMessage **/
const char *csrfp_disablesJsMessage_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        strncpy(config->disablesJsMessage, arg,
            CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH);
    }
    //no else as default config shall come to effect

    return NULL;
}

/** verifyGetFor **/
const char *csrfp_verifyGetFor_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    //#todo: finish this function
    config->verifyGetFor = NULL;        //temp

    return NULL;
}

/** Directives from httpd.conf or .htaccess **/
static const command_rec csrfp_directives[] =
{
    //#todo: verifyGetFor shall have multiple entries, need to check
    AP_INIT_TAKE1("csrfpEnable", csrfp_enable_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "csrfpEnable 'on'|'off', enables the module. Default is 'on'"),
    AP_INIT_TAKE1("csrfpAction", csrfp_action_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "Defines Action to be taken in case of failed validation"),
    AP_INIT_TAKE1("errorRedirectionUri", csrfp_errorRedirectionUri_cmd, NULL,
                RSRC_CONF,
                "Defines URL to redirect if action = 2"),
    AP_INIT_TAKE1("errorCustomMessage", csrfp_errorCustomMessage_cmd, NULL,
                RSRC_CONF,
                "Defines Custom Error Message if action = 3"),
    AP_INIT_TAKE1("jsFilePath", csrfp_jsFilePath_cmd, NULL,
                RSRC_CONF,
                "Absolute url of the js file"),
    AP_INIT_TAKE1("tokenLength", csrfp_tokenLength_cmd, NULL,
                RSRC_CONF,
                "Defines length of csrfp_token in cookie"),
    AP_INIT_TAKE1("disablesJsMessage", csrfp_disablesJsMessage_cmd, NULL,
                RSRC_CONF,
                "<noscript> message to be shown to user"),
    AP_INIT_TAKE1("verifyGetFor", csrfp_verifyGetFor_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "Pattern of urls for which GET request CSRF validation is enabled"),
    { NULL }
};

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
    csrfp_srv_config_create, /* Server config create function */
    NULL,
    csrfp_directives,       /* Any directives we may have for httpd */
    csrfp_register_hooks    /* Our hook registering function */
};
