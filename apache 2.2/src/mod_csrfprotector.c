/**
 * Source code of mod_csrfprotector, Apache Module to mitigate
 * CSRF vulnerability in web applications
 */

/** standard c libs **/
#include "stdio.h"
#include "stdlib.h"
#include "time.h"

/** OpenSSL **/
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/err.h>
#include <openssl/err.h>
#include <openssl/sha.h>

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

/** APRs **/
#include "apr_hash.h"
#include "apr_general.h"
#include "apr_buckets.h"
#include "apr_lib.h"
#include "apr_strings.h"

/** definations **/
#define CSRFP_TOKEN "csrfp_token"
#define DEFAULT_POST_ENCTYPE "application/x-www-form-urlencoded"
#define CSRFP_REGEN_TOKEN "true"
#define CSRFP_CHUNKED_ONLY 0
#define CSRFP_OVERLAP_BUCKET_SIZE 8
#define CSRFP_OVERLAP_BUCKET_DEFAULT "--------"

#define CSRFP_URI_MAXLENGTH 512
#define CSRFP_ERROR_MESSAGE_MAXLENGTH 1024
#define CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH 512
#define CSRFP_VERIFYGETFOR_MAXLENGTH 512
#define CSRFP_GET_RULE_MAX_LENGTH 256

#define DEFAULT_TOKEN_LENGTH 15
#define DEFAULT_TOKEN_MINIMUM_LENGTH 12
#define DEFAULT_ERROR_MESSAGE "<h2>ACCESS FORBIDDEN BY OWASP CSRF_PROTECTOR!</h2>"
#define DEFAULT_REDIRECT_URL ""
#define DEFAULT_JS_FILE_PATH "http://localhost/csrfp_js/csrfprotector.js"
#define DEFAULT_DISABLED_JS_MESSSAGE "This site attempts to protect users against" \
" <a href=\"https://www.owasp.org/index.php/Cross-Site_Request_Forgery_%28CSRF%29\">" \
" Cross-Site Request Forgeries </a> attacks. In order to do so, you must have JavaScript " \
" enabled in your web browser otherwise this site will fail to work correctly for you. " \
" See details of your web browser for how to enable JavaScript."

#define CSRFP_IGNORE_PATTERN ".*(jpg)|(jpeg)|(gif)|(png)|(js)|(css)|(xml)$"
#define CSRFP_IGNORE_TEXT "csrfp_ignore_set"

//=============================================================
// Definations of all data structures to be used later
//=============================================================
typedef enum
{
    true,
    false
} Flag;                         // Flag enum for stating weather to use...
                                // ... mod or not

typedef enum
{
    forbidden,
    strip,
    redirect,
    message,
    internal_server_error
} csrfp_actions;                    // Action enum listing all actions

typedef enum
{
    op_init,                        // States output filter has initiated
    op_body_init,                   // States <body was found, <noscript inserted
    op_body_end,                    // States </body> found, <script inserted
    op_end                          // States output fiter task has finished
} Filter_State;                     // enum of output filter states

typedef enum
{
    nmodified,                      // States Cookie Length not modified
    modified                        // States Cookie Length modified
} Filter_Cookie_Length_State;       // list of cookie length states

typedef struct 
{
    Flag flag;                      // Flag to check if CSRFP is disabled...
                                    // ... true by default
    csrfp_actions action;            // Action Codes, Default - forbidden
    char *errorRedirectionUri;      // Uri to redirect in case action == redirect
    char *errorCustomMessage;       // Message to show in case action == message
    char *jsFilePath;               // Absolute path for JS file
    int tokenLength;                // Length of CSRFP_TOKEN, Default 20
    char *disablesJsMessage;        // Message to be shown in <noscript>
    char *verifyGetFor;       // Path pattern for which GET requests...
                                    // ...Need to be validated as well
    ap_regex_t *ignore_pattern;     // Path pattern for which validation...
                                    // ...is Not needed
} csrfp_config;                      // CSRFP configuraion

typedef struct
{
    char *search;                       // Stores the item being serched (regex) 
    Filter_State state;                 // Stores the current state of filter
    char *script;                       // Will store the js code to be inserted
    char *noscript;                     // Will store the <noscript>..</noscript>...
                                        // ...Info to be inserted
    Filter_Cookie_Length_State clstate; // State of Content-Length header false - for not ...
                                        // ...modified, true for modified or need not modify
    char *overlap_buf;                  // Buffer to store content of current bb->b buffer ...
                                        // ... for next iteration in op filter [el]
} csrfp_opf_ctx;                        // CSRFP output filter context

static csrfp_config *config;
//=============================================================
// Globals
//=============================================================
module AP_MODULE_DECLARE_DATA csrf_protector_module;

// Declarations for functions
static char *generateToken(request_rec *r, int length);
static apr_table_t *read_post(request_rec *r);
static const char *csrfp_strncasestr(const char *s1, const char *s2, int len);
static apr_table_t *csrfp_get_query(request_rec *r);
static char* getCookieToken(request_rec *r);
static csrfp_opf_ctx *csrfp_get_rctx(request_rec *r);

//=============================================================
// Functions
//=============================================================

/**
 * Similar to standard strstr() but case insensitive and lenght limitation
 * (char which is not 0 terminated).
 *
 * @param s1 String to search in
 * @param s2 Pattern to ind
 * @param len Length of s1
 *
 * @return pointer to the beginning of the substring s2 within s1, or NULL
 *         if the substring is not found
 */
static const char *csrfp_strncasestr(const char *s1, const char *s2, int len) {
  const char *e1 = &s1[len-1];
  char *p1, *p2;
  if (*s2 == '\0') {
    /* an empty s2 */
    return((char *)s1);
  }
  while(1) {
    for ( ; (*s1 != '\0') && (s1 <= e1) && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
    if (*s1 == '\0' || s1 > e1) {
      return(NULL);
    }

    /* found first character of s2, see if the rest matches */
    p1 = (char *)s1;
    p2 = (char *)s2;
    for (++p1, ++p2; (apr_tolower(*p1) == apr_tolower(*p2)) && (p1 <= e1); ++p1, ++p2) {
      if((p1 > e1) && (*p2 != '\0')) {
        // reached the end without match
        return NULL;
      }
      if (*p2 == '\0') {
        /* both strings ended together */
        return((char *)s1);
      }
    }
    if (*p2 == '\0') {
      /* second string ended, a match */
      break;
    }
    /* didn't find a match here, try starting at next character in s1 */
    s1++;
  }
  return((char *)s1);
}

/**
 * function to load POST data from request buffer
 *
 * @param: r, request_rec object
 * @param: char buffer to which data is loaded
 *
 * @return: returns 0 on success
 */
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

/**
 * Returns table of POST key-value pair
 *
 * @param: r, request_rec object
 *
 * @return: tbl, apr_table_t table object
 */
static apr_table_t *read_post(request_rec *r)
{
    const char *data;
    const char *key, *val, *type;
    int rc = OK;

    // If not POST, return
    if (r->method_number != M_POST) {
        return NULL;
    }

    type = apr_table_get(r->headers_in, "Content-Type");
    // If content type not appropriate, return
    if (strcasecmp(type, DEFAULT_POST_ENCTYPE) != 0) {
        return NULL;
    }

    // If no data found in POST, return
    if ((rc = util_read(r, &data)) != OK) {
        return NULL;
    }

    apr_table_t *tbl;
    // Allocate memory to POST data table
    tbl = apr_table_make(r->pool, 8);
    while(*data && (val = ap_getword(r->pool, &data, '&'))) {
        key = ap_getword(r->pool, &val, '=');
        ap_unescape_url((char*)key);
        ap_unescape_url((char*)val);
        apr_table_setn(tbl, key, val);
    }

    return tbl;
}

/**
 * Function to retrun current url
 *
 * @param r, request_rec object
 *
 * @return current url (char *)
 * @todo: set to http/https depending upon request r
 */
static char* getCurrentUrl(request_rec *r)
{
    char *retval;
    retval = apr_pstrcat(r->pool, "http://", r->hostname, r->uri, NULL);
    return retval;
}

/**
 * Function to generate a pseudo random no to function as
 * CSRFP_TOKEN
 *
 * @param: length, int
 *
 * @return: token, csrftoken - string
 */
static char* generateToken(request_rec *r, int length)
{
    // #todo - can add symbols like -_.,!+^@ to charset
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK1234567890";
    char *token = NULL;
    token = apr_pcalloc(r->pool, sizeof(char) * length);

    time_t t;
    /* Intializes random number generator */
    srand((unsigned) time(&t));

    if (length) {
        --length;
        int n = 0;
        for ( ; n < length; n++) {
            int key = rand() % (int) (sizeof charset - 1);
            token[n] = charset[key];
        }
        token[length] = '\0';
    }
    return token;
}

/**
 * Returns a table containing the query name/value pairs.
 *
 * @param r, request_rec object
 *
 * @return tbl, Table of NULL if no parameter are available
 */
static apr_table_t *csrfp_get_query(request_rec *r)
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
 * Function to append new CSRFP_TOKEN to output header
 *
 * @param r, request_rec object
 *
 * @return void
 */
static void setTokenCookie(request_rec *r)
{
    csrfp_config *conf = ap_get_module_config(r->server->module_config,
                                                &csrf_protector_module);
    char *token = NULL, *cookie = NULL;

    // Generate a new token
    token = generateToken(r, conf->tokenLength);

    // Send token as cookie header
    cookie = apr_psprintf(r->pool, "%s=%s; Version=1; Path=/;", CSRFP_TOKEN, token);
    apr_table_setn(r->headers_out, "Set-Cookie", cookie);
} 

/**
 * Function to return the token value from cookie
 *
 * @param: r, request_rec
 *
 * @return: CSRFP_TOKEN if exist in cookie, else null
 */
static char* getCookieToken(request_rec *r)
{
    const char *cookie = NULL;
    cookie = apr_table_get(r->headers_in, "Cookie");

    if (!cookie)
        return NULL;

    char *p = strstr(cookie, CSRFP_TOKEN);

    // if csrfp_token doesnot exist
    if (!p)
        return NULL;

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
    apr_cpystrn(tok, &p[strlen(CSRFP_TOKEN) + 1], len);

    return tok;
}

/**
 * Function to validate post token, csrfp_token in POST query parameter
 *
 * @param: r, request_rec pointer
 *
 * @return: int, 0 - for failed validation, 1 - for passed
 */
static int validatePOSTtoken(request_rec *r)
{
    const char* tokenValue = NULL;

    // parse the value from POST query
    apr_table_t *POST;
    POST = read_post(r);

    tokenValue = apr_table_get(POST, CSRFP_TOKEN);

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
 * @param: r, request_rec pointer
 *
 * @return: int, 0 - for failed validation, 1 - for passed
 */
static int validateGETTtoken(request_rec *r)
{
    //get table of all GET key-value pairs
    apr_table_t *GET = NULL;
    GET = csrfp_get_query(r);

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
 * Returns content type of output generated by content generator
 *
 * @param r, request_rec object
 *
 * @return content type, string
 *
 * #todo: make sure we need this function -- else delete
 */
static const char *getOutputContentType(request_rec *r) {
    const char* type = NULL;
    type = apr_table_get(r->headers_out, "Content-Type");
    if (type == NULL) {
        // maybe an error page
        type = apr_table_get(r->err_headers_out, "Content-Type");
    }
    if (type == NULL) {
        type = r->content_type;
    }
    return type;
}

/**
 * Get or create (and init) the pre request context used by the output filter
 *
 * @param r, request_rec object
 * 
 * @return context object for output filter ( csrfp_opf_ctx* )
 */
static csrfp_opf_ctx *csrfp_get_rctx(request_rec *r) {
  csrfp_opf_ctx *rctx = ap_get_module_config(r->request_config, &csrf_protector_module);
  if(rctx == NULL) {
    csrfp_config *conf = ap_get_module_config(r->server->module_config,
                                                &csrf_protector_module);

    rctx = apr_pcalloc(r->pool, sizeof(csrfp_opf_ctx));
    rctx->state = op_init;
    rctx->search = apr_psprintf(r->pool, "<body");

    // Allocate memory and init <noscript> content to be injected
    rctx->noscript = apr_psprintf(r->pool, "\n<noscript>\n%s\n</noscript>",
                                conf->disablesJsMessage);

    // Allocate memory and init <script> content to be injected

    rctx->script = apr_psprintf(r->pool, "\n<script type=\"text/javascript\""
                               " src=\"%s\"></script>\n"
                               "<script type=\"text/JavaScript\">\n"
                               "window.onload = function() {\n"
                               "\t  CSRFP.checkForUrls = [%s];\n"
                               "\t  CSRFP.CSRFP_TOKEN = '%s';\n"
                               "\t  csrfprotector_init();\n"
                               "}\n</script>\n",
                                conf->jsFilePath,
                                (strcmp(conf->verifyGetFor, ""))?conf->verifyGetFor : "",
                                CSRFP_TOKEN);

    rctx->clstate = nmodified;
    rctx->overlap_buf = apr_pcalloc(r->pool, CSRFP_OVERLAP_BUCKET_SIZE);
    apr_cpystrn(rctx->overlap_buf,
        CSRFP_OVERLAP_BUCKET_DEFAULT, CSRFP_OVERLAP_BUCKET_SIZE);

    // globalise this configuration
    ap_set_module_config(r->request_config, &csrf_protector_module, rctx);
  }
  return rctx;
}

/**
 * Injects a new bucket containing a reference to the javascript.
 *
 * @param r, request_rec object
 * @param bb, bucket_brigade object
 * @param b Bucket to split and insert date new bucket at the postion of the marker
 * @param rctx Request context containing the state of the parser
 * @param buf String representation of the bucket
 * @param sz Position to split the bucket and insert the new content
 * @param flag, 0 - for <noscript> insertion, 1 for <script> insertion
 *
 * @return Bucket to continue searching (at the marker)
 */
static apr_bucket *csrfp_inject(request_rec *r, apr_bucket_brigade *bb, apr_bucket *b,
                                    csrfp_opf_ctx *rctx, const char *buf,
                                    apr_size_t sz, int flag) {
    apr_bucket *e;
    apr_bucket_split(b, sz);
    b = APR_BUCKET_NEXT(b);

    const char* insert = (flag == 1)? rctx->script : rctx->noscript;

    e = apr_bucket_pool_create(insert, strlen(insert), r->pool, bb->bucket_alloc);

    APR_BUCKET_INSERT_BEFORE(b, e);

    if (flag) {
        // script has been injected
        rctx->state = op_body_end;
        rctx->search = NULL;
    } else {
        // <noscript> has been injected
        rctx->state = op_body_init;
        apr_cpystrn(rctx->search, "</body>", strlen("</body>"));
    }

    return b;
}

/**
 * Returns appropriate status code, as per configuration
 * For failed validation action
 *
 * @param r, request_rec object
 *
 * @return int, status code for action
 */
static int failedValidationAction(request_rec *r)
{
    csrfp_config *conf = ap_get_module_config(r->server->module_config,
                                                &csrf_protector_module);
    
    // Log the failure
    ap_log_rerror(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, r,
                      "CSRF ATTACK, %s, action=%d, method=%s", 
                      conf->action == strip ? "strip & served" : "denied",
                      conf->action,
                      (!strcmp(r->method, "GET"))? "GET" : "POST");

    switch (conf->action)
    {
        case forbidden:
            return HTTP_FORBIDDEN;
            break;
        case strip:
            // Strip POST values - and forward the request
            if (!strcmp(r->method, "GET")
                && r->args) {
                apr_cpystrn(r->args, "\0", 1);
            } else if (!strcmp(r->method, "POST")) {
                // #todo: code to perform this
            }
            return OK;
            break;
        case redirect:
            // Redirect to custom uri
            if (strlen(conf->errorRedirectionUri) > 0) {
                apr_table_add(r->headers_out, "Location", conf->errorRedirectionUri);
                return HTTP_MOVED_PERMANENTLY;
            } else {
                return HTTP_FORBIDDEN;
            }
            break;
        case message:
            // Show custom Error Message
            ap_rprintf(r, "<h2>%s</h2>", conf->errorCustomMessage);
            return DONE;
            break;
        case internal_server_error:
            // Show internel Server error
            return HTTP_INTERNAL_SERVER_ERROR;
            break;
        default:
            // Default action is FORBIDDEN
            return HTTP_FORBIDDEN;
            break;
    }
}

/**
 * Function to decide weather to validate current request
 * Depending upon requested file, matched against ignore pattern
 *
 * @param: r, request_rec object
 *
 * @return: int, - 1 if validation needed, 0 otherwise
 */
static int needvalidation(request_rec *r)
{
    /**
     * #ask: do we need to log cases when we do not validate?
     */
    if (apr_table_get(r->subprocess_env, CSRFP_IGNORE_TEXT))
        return 0;

    csrfp_config *conf = ap_get_module_config(r->server->module_config,
                                                &csrf_protector_module);
    if(r->parsed_uri.path) {
        const char *path = strrchr(r->parsed_uri.path, '/');
        // faster than match against a long string
        if(path == NULL) {
            path = r->parsed_uri.path;
        }
        if(ap_regexec(conf->ignore_pattern, path, 0, NULL, 0) == 0) {
            apr_table_addn(r->subprocess_env, CSRFP_IGNORE_TEXT, "m");
            return 0;
        }
    }
    return 1;
}

//=====================================================================
// Handlers -- call back functions for different hooks
//=====================================================================
/**
 * Callback function for header parser by Hook Registering function
 *
 * @param r, request_rec object
 *
 * @return status code, int
 */
static int csrfp_header_parser(request_rec *r)
{
    csrfp_config *conf = ap_get_module_config(r->server->module_config,
                                                &csrf_protector_module);
    if (conf->flag == false) 
        return OK;

    if (!needvalidation(r)) {
        // No need of validation, go ahead!
        return OK;
    }

    // If request type is POST
    // Need to check configs weather or not a validation is needed POST
    if ( !strcmp(r->method, "POST")
        && !validatePOSTtoken(r)) {
            
        // Log this --
        // Take actions as per configuration
        return failedValidationAction(r);

    } else if ( !strcmp(r->method, "GET") ) {
        apr_pool_t **pool;
        apr_pool_create(pool, r->pool);

        char **arr;
        int loop = 0;

        char* patterns = apr_pstrdup(*pool, config->verifyGetFor);
        apr_table_addn(r->headers_out, "test", patterns);
        apr_strtok(patterns, "','", arr);

        const char *currentUrl = getCurrentUrl(r);
        
        while (arr != NULL) {
            ap_regex_t* pattern;
            pattern = (ap_regex_t*) apr_pcalloc(*pool, sizeof pattern);
            
            if (loop == 0) {
                // Means first elem -- remove init `'`
                int len = strlen(*arr), i;
                for (i = 0; i < len; i++) {
                    **arr = *(*arr+1);
                }
                *arr[len - 1] = '\0';
                if ((arr + 1) == NULL)
                    *arr[len - 2] = '\0';  // if only elem                 
            } else if ((arr + 1) == NULL) {
                *arr[strlen(*arr) - 1] = '\0';  // Last elem -- remove trailing `'`
            }

            ap_regcomp(pattern, *arr, 0);
            if (ap_regexec(pattern, currentUrl, 0, NULL, 0) == 0) {
                if (!validateGETTtoken(r)) {
                    // --free the pool its not needed anymore
                    apr_pool_clear(*pool);

                    // Means pattern matched && validation failed
                    // Log this --
                    // Take actions as per configuration
                    return failedValidationAction(r);
                }
                break;
            }
            ++arr; ++loop;
        }
        apr_pool_clear(*pool);
    }

    // Information for output_filter to regenrate token and
    // append it to output header -- Regenrate token
    // Section to regenrate and send new Cookie Header (csrfp_token) to client
    apr_table_add(r->subprocess_env, "regen_csrfptoken", CSRFP_REGEN_TOKEN);

    // Add environment variable for php to inform request has been
    //      validated by mod_csrfp
    apr_table_add(r->subprocess_env, "mod_csrfp_enabled", "true");

    // Appends X-Protected-By header to output header
    apr_table_addn(r->headers_out, "X-Protected-By", "CSRFP 0.0.1");
    return OK;
}

/**
 * Filters output generated by content generator and modify content
 *
 * @param f, apache filter object
 * @param bb, apache brigade object
 *
 * @return apr_status_t code
 */
static apr_status_t csrfp_out_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    /**
     * if request  file is image or js, ignore the filter on the top itself
     */
    if (!needvalidation(r)) {
        // No need of validation, go ahead!
        ap_remove_output_filter(f);
        return ap_pass_brigade(f->next, bb);
    }

    // Get the context config
    csrfp_opf_ctx *rctx = csrfp_get_rctx(r);
    
    //apr_table_addn(r->headers_out, "output_filter", "Arrival Confirmed");

    /*
     * - Determine if it's html and force chunked response
     * - search <body to insert <noscript> .. </noscript> info
     * - search </body> to insert script
     * - set csrfp_token cookie
     * - end (all done)
     */
    if(rctx->state == op_init) {
        const char *type = getOutputContentType(r);
        if(type == NULL || ( strncasecmp(type, "text/html", 9) != 0
            && strncasecmp(type, "text/xhtml", 10) != 0) ) {
            // we don't want to parse this response (no html)
            rctx->state = op_end;
            rctx->search = NULL;
            ap_remove_output_filter(f);
        } else {
            // start searching head/body to inject our script

            // -- need to modify the Content-Length header
            if(CSRFP_CHUNKED_ONLY) {
                // send as chunked response
                apr_table_unset(r->headers_out, "Content-Length");
                apr_table_unset(r->err_headers_out, "Content-Length");
                r->chunked = 1;
                rctx->clstate = modified;  // Content-Length need not be modified anymore
            } else {
                // Modify the content-length header -- if available
                /**
                 * #todo: probably Content-Length is not generated by the time this hook is called
                 *          So we might want this be done by later hook
                 */
                int errh = 0;
                const char* cl =  apr_table_get(r->headers_out, "Content-Length");
                if(!cl) {
                    errh = 1;
                    cl =  apr_table_get(r->err_headers_out, "Content-Length");
                }

                if(cl) {
                    // adjust non-chunked response
                    char *length;
                    apr_off_t s;
                    char *errp = NULL;
                    if(apr_strtoff(&s, cl, &errp, 10) == APR_SUCCESS) {
                        s = s + strlen(rctx->script) + strlen(rctx->noscript);
                        length = apr_psprintf(r->pool, "%"APR_OFF_T_FMT, s);
                        if(!errh) {
                            apr_table_set(r->headers_out, "Content-Length", length);
                        } else {
                            apr_table_set(r->err_headers_out, "Content-Length", length);
                        }
                    } else {
                        // fallback to chunked
                        r->chunked = 1;
                        if(!errh) {
                            apr_table_unset(r->headers_out, "Content-Length");
                        } else {
                            apr_table_unset(r->err_headers_out, "Content-Length");
                        }
                    }

                    rctx->clstate = modified;  // Content-Length need not be modified anymore
                } else {
                    // This means Content-Length header has not yet been generated
                    // #todo need to do something about this

                }
            }
        }
    }

    // start searching within this brigade...
    if (rctx->search) {
        apr_bucket *b;

        for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
            if (APR_BUCKET_IS_EOS(b)) {
                /* If we ever see an EOS, make sure to FLUSH. */
                apr_bucket *flush = apr_bucket_flush_create(f->c->bucket_alloc);
                APR_BUCKET_INSERT_BEFORE(b, flush);
            }

            if (!(APR_BUCKET_IS_METADATA(b))) {
                const char *buf;
                apr_size_t nbytes;
                int findBracketOnly = 0;
                /**
                 * Concept: While searching for a string say '<body(.*)>' in a buffer
                 * 4 cases are possible in a bucket
                 *  1. '<body' found & '>' found
                 *  2. '<body' found & '>' not found i.e. '>' in next bucket
                 *  3. '<body' not found, but cause of bucket overlap, for ex
                 *      ... '<bo' in one bucket, 'dy(.*)>' in another
                 *  4. '<body' not found, no overlap issue
                 */
                restart:
                if (apr_bucket_read(b, &buf, &nbytes, APR_BLOCK_READ) == APR_SUCCESS) {
                    if (nbytes > 0) {
                        // Create a new string = overlap_buf + buf
                        const char *nbuf = apr_pstrcat(r->pool, rctx->overlap_buf,
                                                buf, NULL);
                        const char *marker = NULL;
                        apr_size_t sz;
                        marker = csrfp_strncasestr(nbuf, rctx->search, nbytes);
                        //apr_table_addn(r->headers_out, "xyz", marker);
                        if (marker || findBracketOnly) {
                            // ..search was found
                            if (rctx->state == op_init
                                || findBracketOnly) {

                                // Seach for '<body' now searching for first '>'
                                // Or checking if it does not exist in current bucket
                                apr_size_t buflen = strlen(buf);

                                // Setting for case - 2, '<body' found in prev bucket
                                apr_size_t markerlen = 0;
                                apr_size_t sz = 0;
                                const char *c = buf;

                                if (!findBracketOnly) {
                                    // setting for case - 1 '<body' in same bucket
                                    markerlen = strlen(marker);
                                    sz = buflen - markerlen;
                                    c = marker;
                                }

                                int offset = 0, flag = 0;
                                for ( ; *c != '>'; offset++, c++) {
                                    if ((offset + markerlen) == buflen) {
                                        ++flag;
                                        break;
                                    }
                                }

                                if (!flag) {
                                    // case - 1, <body and > in same bucket
                                    sz += ++offset;
                                    b = csrfp_inject(r, bb, b, rctx, buf, sz, 0);
                                    findBracketOnly = 0;
                                } else {
                                    // case - 2, <body found, need to find > in next buffer
                                    b = APR_BUCKET_NEXT(b);
                                    ++findBracketOnly;
                                }
                                
                                goto restart;
                            } else if (rctx->state == op_body_init) {
                                apr_size_t sz = strlen(buf) - strlen(marker) + sizeof("</body>") - 1;
                                b = csrfp_inject(r, bb, b, rctx, buf, sz, 1);
                            }
                        } else {
                            // case - 3 or 4 '<body' not found in current bucket
                            const char *cptr = buf + (sizeof buf) - CSRFP_OVERLAP_BUCKET_SIZE;
                            apr_cpystrn(rctx->overlap_buf, cptr, CSRFP_OVERLAP_BUCKET_SIZE);
                        }
                    }
                }
            }
        }
    }
    
    const char *regenToken = apr_table_get(r->subprocess_env, "regen_csrfptoken");
    if (regenToken && !strcasecmp(regenToken, CSRFP_REGEN_TOKEN)) {
        /*
         * - Regenrate token
         * - Send it as output header
         */
        setTokenCookie(r);
    }
    return ap_pass_brigade(f->next, bb);
}

/**
 * Registers op filter -- csrfp_out_filter
 *
 * @param: r,request_rec object
 *
 * @return void
 */
static void csrfp_insert_filter(request_rec *r)
{
    ap_add_output_filter("csrfp_out_filter", NULL, r, r->connection);
}

/**
 * Handler to allocate memory to config object
 * And allocae default values to variabled
 *
 * @param: standard parameters, @return void
 */
static void *csrfp_srv_config_create(apr_pool_t *p, server_rec *s)
{
    // Registering default configurations
    config = apr_pcalloc(p, sizeof(csrfp_config));
    config->flag = true;
    config->action = forbidden;
    config->tokenLength = DEFAULT_TOKEN_LENGTH;

    // Allocates memory, and assign defalut value For jsFilePath
    config->jsFilePath = apr_pcalloc(p, CSRFP_URI_MAXLENGTH);
    apr_cpystrn(config->jsFilePath, DEFAULT_JS_FILE_PATH,
            CSRFP_URI_MAXLENGTH);

    // Allocates memory, and assign defalut value For errorRedirectionUri
    config->errorRedirectionUri = apr_pcalloc(p, CSRFP_URI_MAXLENGTH);
    apr_cpystrn(config->errorRedirectionUri, DEFAULT_REDIRECT_URL,
            CSRFP_URI_MAXLENGTH);

    // Allocates memory, and assign defalut value For errorCustomMessage
    config->errorCustomMessage = apr_pcalloc(p, CSRFP_ERROR_MESSAGE_MAXLENGTH);
    apr_cpystrn(config->errorCustomMessage, DEFAULT_ERROR_MESSAGE,
            CSRFP_ERROR_MESSAGE_MAXLENGTH);

    // Allocates memory, and assign defalut value For disablesJsMessage
    config->disablesJsMessage = apr_pcalloc(p, CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH);
    apr_cpystrn(config->disablesJsMessage, DEFAULT_DISABLED_JS_MESSSAGE,
            CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH);

    // Allocate memory and set regex for ignore-pattern regex object
    config->ignore_pattern = ap_pregcomp(p, CSRFP_IGNORE_PATTERN, AP_REG_ICASE);

    config->verifyGetFor = apr_pcalloc(p,CSRFP_VERIFYGETFOR_MAXLENGTH);
    apr_cpystrn(config->verifyGetFor, "", CSRFP_VERIFYGETFOR_MAXLENGTH);

    return config;
}

//=============================================================
// Configuration handler functions 
//=============================================================

/** csrfEnable **/
const char *csrfp_enable_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(!strcasecmp(arg, "off")) config->flag = false;
    else config->flag = true;
    return NULL;
}

/** csrfAction **/
const char *csrfp_action_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(!strcasecmp(arg, "forbidden"))
        config->action = forbidden;
    else if (!strcasecmp(arg, "strip"))
        config->action = strip;
    else if (!strcasecmp(arg, "redirect"))
        config->action = redirect;
    else if (!strcasecmp(arg, "message"))
        config->action = message;
    else if (!strcasecmp(arg, "internal_server_error"))
        config->action = internal_server_error;
    else config->action = forbidden;       //default

    return NULL;
}

/** errorRedirectionUri **/
const char *csrfp_errorRedirectionUri_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        apr_cpystrn(config->errorRedirectionUri, arg,
        CSRFP_URI_MAXLENGTH);
    }
    else config->errorRedirectionUri = NULL;

    return NULL;
}

/** errorCustomMessage **/
const char *csrfp_errorCustomMessage_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        apr_cpystrn(config->errorCustomMessage, arg,
        CSRFP_ERROR_MESSAGE_MAXLENGTH);
    }
    else config->errorCustomMessage = NULL;

    return NULL;
}

/** jsFilePath **/
const char *csrfp_jsFilePath_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        apr_cpystrn(config->jsFilePath, arg,
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
        if (length < DEFAULT_TOKEN_MINIMUM_LENGTH
            || !length)
            return NULL;
        config->tokenLength = length;
    }
    //no else as default config shall come to effect

    return NULL;
}

/** disablesJsMessage **/
const char *csrfp_disablesJsMessage_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        apr_cpystrn(config->disablesJsMessage, arg,
            CSRFP_DISABLED_JS_MESSAGE_MAXLENGTH);
    }
    //no else as default config shall come to effect

    return NULL;
}

/** verifyGetFor **/
const char *csrfp_verifyGetFor_cmd(cmd_parms *cmd, void *cfg, const char *arg)
{
    if(strlen(arg) > 0) {
        apr_cpystrn(config->verifyGetFor, arg,
            CSRFP_VERIFYGETFOR_MAXLENGTH);
    }

    return NULL;
}

/** Directives from httpd.conf or .htaccess **/
static const command_rec csrfp_directives[] =
{
    AP_INIT_TAKE1("csrfpEnable", csrfp_enable_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "csrfpEnable 'on'|'off', enables the module. Default is 'on'"),
    AP_INIT_TAKE1("csrfpAction", csrfp_action_cmd, NULL,
                RSRC_CONF|ACCESS_CONF,
                "Defines Action to be taken in case of failed validation"),
    AP_INIT_TAKE1("errorRedirectionUri", csrfp_errorRedirectionUri_cmd, NULL,
                RSRC_CONF,
                "Defines URL to redirect if action = redirect"),
    AP_INIT_TAKE1("errorCustomMessage", csrfp_errorCustomMessage_cmd, NULL,
                RSRC_CONF,
                "Defines Custom Error Message if action = message"),
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

static int csrfp_post_processing_hook(request_rec *r)
{
    ap_add_output_filter("csrfp_op_content_length_filter", NULL, r, r->connection);
}

/**
 * Hook registering function for mod_csrfp
 * @param: pool, apr_pool_t
 */
static void csrfp_register_hooks(apr_pool_t *pool)
{
    // Create hooks in the request handler, so we get called when a request arrives

    // Handler to parse incoming request and validate incoming request
    ap_hook_header_parser(csrfp_header_parser, NULL, NULL, APR_HOOK_FIRST);

    // Handler to modify output filter
    ap_register_output_filter("csrfp_out_filter", csrfp_out_filter, NULL, AP_FTYPE_RESOURCE);

    ap_hook_insert_filter(csrfp_insert_filter, NULL, NULL, APR_HOOK_MIDDLE);
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
