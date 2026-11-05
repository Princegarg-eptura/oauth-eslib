/**
 * Copyright (c) 2015 iOffice
 * @version v0.0.2
 */

(function(){

"use strict";

angular.module('oauth', []);

/**
 * Check if the input object has all the keys specified in the
 * array of `attributes`.
 *
 * @param {Object} obj The object in question.
 * @param {Array} attributes The required attributes.
 * @returns {boolean}
 */
function hasAttributes(obj, attributes) {
  var intersection = _.intersection(_.keys(obj), attributes);
  return intersection.length == attributes.length;
}


angular.module('oauth')
  .factory('oauthIOffice', ['OAuth', 'oaHost', '$http', '$location', oaIOffice]);


/**
 * The `OAuth` service provides functions to provide information about
 * the user who is logged in and to make rest api calls.
 */
function oaIOffice(OAuth, oaHost, $http, $location) {

  var config = {
    token: '/external/api/oauth2/token',
    revoke: '/external/api/oauth2/revoke',
    tokenInfo: '/external/api/oauth2/tokeninfo'
  };
  return {
    requestToken: requestToken,
    refreshToken: refreshToken,
    verifyToken: verifyToken,
    logout: logout,
    onAccessDenied: onAccessDenied,
    getAccessHeaders: getAccessHeaders,
    badCredentials: badCredentials
  };


  /**
   * Exchanges an authorization code by an access token.
   */
  function requestToken(code) {
    oaHost.loadHost();
    return $http({
      method: "post",
      url: oaHost.composeAPIPath(config.token),
      headers: {
        'Content-type': 'application/json',
        'x-grant-type': 'authorization_code',
        'x-redirect-uri': oaHost.redirectUri,
        'x-client-id': oaHost.clientId,
        'x-scope': oaHost.scope,
        'x-auth-code': code
      }
    }).then(
      function(response) {
        return OAuth.accessAllowed(response.data);
      },
      function(response) {
        if (!response.data) { return OAuth.accessUnavailable('requestToken'); }
        var dat = response.data,
          reason = dat.error + ': ' + dat.errorDescription;
        return OAuth.accessDenied(reason);
      }
    );
  }


  /**
   * Attempts to obtain and set a new token via the refresh token.
   * You may catch the event `oauth:refreshTokenError` to handle
   * the event when we cannot retrieve a new access token. The event
   * comes along with an object with properties `status`, `error` and
   * `errorDescription`.
   */
  function refreshToken(token) {
    oaHost.loadHost();
    return $http({
      method: "post",
      url: oaHost.composeAPIPath(config.token),
      headers: {
        'Content-type': 'application/json',
        'x-grant-type': 'refresh_token',
        'x-redirect-uri': oaHost.redirectUri,
        'x-client-id': oaHost.clientId,
        'x-scope': oaHost.scope,
        'x-refresh-token': token
      }
    }).then(
      function(response) {
        return OAuth.accessAllowed(response.data);
      },
      function(response) {
        if (!response.data) { return OAuth.accessUnavailable('refreshToken'); }
        var dat = response.data,
          reason = dat.error + ': ' + dat.errorDescription;
        return OAuth.accessDenied(reason);
      }
    );
  }


  /**
   * Return a promise to inform us if the token is valid. The
   * promise will return an object with the attributes `status`
   * and `reason`. A true status means that the token is valid.
   * When the token is invalid the `reason` property will be set.
   */
  function verifyToken(accessToken) {
    return $http({
      method: "get",
      url: oaHost.composeAPIPath(config.tokenInfo),
      headers: {
        'x-token': accessToken
      }
    }).then(
      function() {
        return OAuth.accessAllowed();
      },
      function(response) {
        if (!response.data) { return OAuth.accessUnavailable('verifyToken'); }
        var dat = response.data,
          reason = dat.error + ': ' + dat.errorDescription;
        return OAuth.accessDenied(reason);
      }
    );
  }


  /**
   * Removes the token and informs the server that the token is no
   * longer needed.
   */
  function logout(accessToken) {
    return $http({
      method: "get",
      url: oaHost.composeAPIPath(config.revoke),
      headers: {
        'x-token': accessToken
      }
    });
  }


  /**
   * Send user to the app root. This function is invasive but it is
   * being presented here to point out that if the module defines
   * this function then the OAuth service will call the function when
   * the access is denied. To change the behaviour make sure to
   * overwrite this function, i.e. oaIOffice.onAccessDenied = null;
   *
   * You may expect to have two inputs: reason and location. Location
   * may not always be set.
   */
  function onAccessDenied() {
    $location.path('/');
  }


  /**
   * Get an object with the iOffice access headers.
   *
   * @returns {Object} The authorization headers
   */
  function getAccessHeaders() {
    if ('oauth-dev' in window.localStorage) {
      var data = window.localStorage['oauth-dev'].split(',');
      var user = data[2], pass = data[3];
      return {
        'x-auth-username': user,
        'x-auth-password': pass
      };
    }
    return {
      'x-access-token': OAuth.getAccessToken()
    };
  }


  /**
   * Return true if the error response was due to bad credentials.
   *
   * The contents of the method are already implemented in
   * the OAuth service. We may remove this function from the iOffice
   * module and it will behave correctly. This is written here to
   * show how to overwrite the default. This is not done in the
   * iOffice module but we can do a similar function called:
   * "mayRefresh" which checks if the error response allows us to
   * refresh the token (by default it checks if the status was 403).
   *
   * @returns {Boolean} True if error due to bad credentials.
   */
  function badCredentials(response) {
    return (response.status == 401);
  }

}

angular.module('oauth')
    .factory('oaRecovery', ['$q', '$injector', OAuthRecovery])
    .config(['$httpProvider', function($httpProvider) {
      $httpProvider.interceptors.push('oaRecovery');
    }]);


/**
 * Intercepts http error responses and checks if the errors are due
 * to bad credentials or insufficient permissions (may refresh). It
 * handles the responses according the host.
 *
 */
function OAuthRecovery($q, $injector) {
  return {
    responseError: responseError
  };

  function responseError(response) {
    var $http = $injector.get('$http'),
        OAuth = $injector.get('OAuth'),
        oaLog = $injector.get('oaLog'),
        deferred = $q.defer(),
        reason;

    if (OAuth.badCredentials(response)) {

      oaLog.debug('OAuth::Recovery', 'Request failed due to bad credentials...');
      reason = "access_denied: The server does not recognize the credentials.";
      OAuth.onAccessDenied(reason);
      response.status = 0;
      return $q.reject(response);

    } else if (OAuth.mayRefresh(response)) {

      if (OAuth.getRefreshToken()) {

        oaLog.debug('OAuth::Recovery', 'Request failed but we may be able to recover...');
        OAuth.refreshToken().then(deferred.resolve, deferred.reject);
        return deferred.promise.then(function() {
          OAuth.setAccessHeaders(response.config.headers);
          return $http(response.config);
        });

      } else {

        oaLog.debug('OAuth::Recovery', 'Request failed while using the implicit grant, cannot recover...');
        reason = "access_denied: Cannot obtain automatic access while using the implicit grant.";
        OAuth.onAccessDenied(reason);
        return $q.reject(response);

      }

    }
    return $q.reject(response);
  }
}

/**
 * The `OAuth` service provides functions to facilitate the
 * interaction with with different oauth service providers.
 *
 */
function OAuth(oaToken, oaHost, oaHash, oaLog, $q, $http) {

  /**
   * A note about the following private variables.
   *
   * `inProgress` is used by `submitRequest`. This is an object
   * keeping track of named request so that requests are not repeated.
   * Instead we obtain the promised that was returned the first time
   * the request was sent. See comments on `submitRequest` for more
   * information.
   *
   * `hostMap` will become an object once the `init` function is
   * fired. The `init` function needs to be called during the
   * configuration of the application so that we may provide a map
   * of services that have the following methods:
   *
   * - requestToken
   * - refreshToken
   * - verifyToken
   * - logout
   * - onAccessDenied
   * - getAccessHeaders
   * - [badCredentials]
   * - [mayRefresh]
   *
   * The last two methods are optional. An example of how to use
   * init goes as follows:
   *
   *    OAuth.init({
   *      google: GoogleService,
   *      twitter: twitterService,
   *      ioffice: iOfficeService
   *    });
   *
   */
  var inProgress = {},
      hostMap = null;
  return {
    init: init,
    login: login,

    submitRequest: submitRequest,
    hasToken: hasToken,
    accessDenied: accessDenied,
    accessAllowed: accessAllowed,
    accessUnavailable: accessUnavailable,
    hasAccess: hasAccess,
    getAccessToken: getAccessToken,
    getRefreshToken: getRefreshToken,
    getHostSite: getHostSite,
    composeAPIPath: oaHost.composeAPIPath,

    getHostService: getHostService,
    requestToken: requestToken,
    refreshToken: refreshToken,
    verifyToken: verifyToken,
    logout: logout,
    onAccessDenied: onAccessDenied,
    setAccessHeaders: setAccessHeaders,
    badCredentials: badCredentials,
    mayRefresh: mayRefresh
  };

  /**
   * The init method must be called right when the app starts. This
   * will initialize the host map.
   *
   * @param {Object} map An object mapping strings to specialized
   *                services for the OAuth service.
   */
  function init(map) {
    hostMap = map;
    if ('oauth-dev' in window.localStorage) {
      var data = window.localStorage['oauth-dev'].split(',');
      var host = data[0], site = data[1];
      oaHost.storeHost({
        host: host,
        site: site,
        clientId: 'dev',
        redirectUri: 'dev',
        authorizePath: 'dev'
      });
    }
  }

  /**
   * Submit the host information and attempt to login. The params
   * object should be an object with the following attributes:
   *
   * - host:          // (required) The host name, this is one of the
   *                                names assigned during the call
   *                                to the init function.
   * - site:          // (required) set the oauth server host (e.g.
   *                                http://oauth.example.com)
   * - clientId:      // (required) client id
   * - redirectUri:   // (required) client redirect uri
   * - authorizePath: // (required) authorization url
   *
   * - clientSecret:  // (optional) client secret
   * - scope:         // (optional) scope
   * - state:         // (optional) An arbitrary unique string created
   *                                by your app to guard against
   *                                Cross-site Request Forgery
   *
   * - responseType:  // (optional) response type, defaults to code.
   *                                Use 'token' for implicit flow and
   *                                'code' for authorization code flow.
   *
   * @param {Object} params The host parameters.
   * @returns {Object} An object with three promises. The first one
   *                   is a promise to let us know if the host site
   *                   loaded. The second one tells us when the
   *                   host site closes. The last one promises to let
   *                   us know when we obtain the token. The three
   *                   promises are called `loadSite`, `exitSite` and
   *                   `loadToken`.
   */
  function login(params, isIOS, iOSAWAS) {

    params.state = params.state || (new Date()).valueOf();
    if (oaHost.storeHost(params) === null) {
      throw 'OAuth.login did not receive the required parameters.';
    }

    var task = {
        loadSite: $q.defer(),
        exitSite: $q.defer(),
        loadToken: $q.defer()
      },
      url = oaHost.composeAuthPath({
        response_type: params.responseType || 'code'
      }),
      redirectUri = oaHost.redirectUri,
      isMobile = (document.location.href.indexOf('file://') === 0 || !!window.cordova || document.location.hostname === 'localhost'),
      isHostSite = function(url) {
        return (url.indexOf(oaHost.site) === 0);
      },
      isAppSite = function(url) {
        return (url.indexOf(redirectUri) === 0);
      },
      processQuery = function(query, loadTokenTask) {
        var queryParams = oaHash.parse(query);
        if (_.has(queryParams, 'code')) {
          var authCode = queryParams.code;
          delete queryParams.code;
          oaLog.debug('OAuth.login', 'code in query...');
          requestToken(authCode).then(function() {
            oaLog.debug('OAuth.login', 'requestToken success.');
            loadTokenTask.resolve();
          }, function() {
            oaLog.debug('OAuth.login', 'requestToken error.');
            loadTokenTask.reject();
          });
        } else if (_.has(queryParams, 'access_token')) {
          oaLog.debug('OAuth.login', 'access_token in query...');
          console.error("Not done yet...");
        } else {
          oaLog.debug('OAuth.login', 'No known variables in query...');
          loadTokenTask.reject();
        }
        window.localStorage['oauth-query'] = JSON.stringify(queryParams);
      },
      setupInAppBrowserListeners = function(ref, loadTokenTask, loadSiteTask, exitSiteTask) {

        // Regular browser popup (localhost dev): use window.postMessage instead of
        // InAppBrowser loadstart events, which don't exist on a standard popup window.
        // The oauth2redirect.html page posts { type: 'oauth-redirect', url: <full href> }
        // after the dev redirect server forwards the callback to localhost:8100.
        if (document.location.hostname === 'localhost') {
          var messageHandler = function(event) {
            if (!event.data || event.data.type !== 'oauth-redirect') return;
            window.removeEventListener('message', messageHandler);
            var url = event.data.url;
            var queryIdx = url.indexOf('?');
            var query = queryIdx !== -1 ? url.substring(queryIdx + 1) : '';
            exitSiteTask.resolve();
            loadSiteTask.resolve('load_success');
            if (ref && !ref.closed) ref.close();
            processQuery(query, loadTokenTask);
          };
          window.addEventListener('message', messageHandler);
          return;
        }

        function iabLoadStart(event) {
          if (isAppSite(event.url)) {
            exitSiteTask.resolve();
            ref.close();
            oaLog.debug('OAuth.login:InAppBrowser', 'Got a query from host site.');
            var query = (event.url).substring(redirectUri.length + 1);
            processQuery(query, loadTokenTask);

          }
        }

        function iabLoadStop(event) {
          if (isHostSite(event.url)) {
            // The load site promise may be fired more than once
            // if we use SAML. This is because the site loads first
            // then it goes to Okta, then finally it comes back to
            // the app site.
            oaLog.debug('OAuth.login:InAppBrowser', 'Host site is done loading.');
            loadSiteTask.resolve("load_success");
            ref.removeEventListener('loadstop', iabLoadStop);
            ref.show();
          }
        }

        function iabLoadError(event) {
          if (!isAppSite(event.url)) {
            oaLog.debug('OAuth.login:InAppBrowser', 'Error loading: ' + event.url);
            loadSiteTask.reject("load_error");
            loadTokenTask.reject();
            exitSiteTask.resolve();
            accessUnavailable('login:loadError');
            ref.close();
          }
        }

        function iabClose() {
          ref.removeEventListener('loadstart', iabLoadStart);
          ref.removeEventListener('loadstop', iabLoadStop);
          ref.removeEventListener('loaderror', iabLoadError);
          ref.removeEventListener('exit', iabClose);
        }

        ref.addEventListener('loadstart', iabLoadStart);
        ref.addEventListener('loadstop', iabLoadStop);
        ref.addEventListener('loaderror', iabLoadError);
        ref.addEventListener('exit', iabClose);

      },

      // setupSystemBrowserListeners: used on device with _system browser.
      // cordova-plugin-customurlscheme fires window.handleOpenURL(url) when the
      // iomaintenance:// deep link is opened. index.html stores the URL in
      // localStorage['launchUrl'] and postMessages 'oauth2redirectfromsystembrowser-ready'.
      setupSystemBrowserListeners = function(loadTokenTask, exitSiteTask) {
        function onSystemBrowserRedirect(event) {
          if (event.data !== 'oauth2redirectfromsystembrowser-ready') return;
          window.removeEventListener('message', onSystemBrowserRedirect);
          try {
            var stored = JSON.parse(window.localStorage.getItem('launchUrl') || 'null');
            if (stored && stored.data) {
              var storedUrl = stored.data;
              var query = storedUrl.substring(redirectUri.length + 1);
              window.localStorage.removeItem('launchUrl');
              processQuery(query, loadTokenTask);
              exitSiteTask.resolve('system_browser_redirect');
            } else {
              loadTokenTask.reject('no_launch_url');
            }
          } catch (e) {
            loadTokenTask.reject('parse_error');
          }
        }
        window.addEventListener('message', onSystemBrowserRedirect);
      };

    oaLog.debug('OAuth.login', 'Checking for site availability...');
    if (isIOS && iOSAWAS) {
      // iOS 12+: use ASWebAuthenticationSession — handles the custom URL scheme redirect
      // internally without needing handleOpenURL or a system browser workaround.
      oaLog.debug('OAuth.login', 'iOS: using ASWebAuthenticationSession.');
      task.loadSite.resolve('aswebauth_start');
      iOSAWAS.start('iomaintenance', url)
        .then(function(redirectUrl) {
          var query = '';
          if (redirectUrl.indexOf('#') > -1) query = redirectUrl.split('#')[1];
          else if (redirectUrl.indexOf('?') > -1) query = redirectUrl.split('?')[1];
          else query = redirectUrl.replace(redirectUri + '#', '').replace(redirectUri + '?', '');
          processQuery(query, task.loadToken);
          task.exitSite.resolve('aswebauth_complete');
        })
        .catch(function(err) {
          console.error('[OAuth] ASWebAuthenticationSession error:', err);
          task.loadSite.reject('aswebauth_error');
          task.loadToken.reject('aswebauth_error');
          task.exitSite.resolve('aswebauth_cancelled');
        });
    // In a browser (localhost dev via ionic serve, no cordova), skip the cross-origin XHR
    // site check. NOTE: on device, content is also served from https://localhost/ but
    // window.cordova IS defined — must NOT use the popup path there.
    } else if (document.location.hostname === 'localhost' && !window.cordova) {
      oaLog.debug('OAuth.login', 'localhost: skipping CORS-blocked site check.');
      var ref = window.open(url, '_blank', 'location=yes,toolbar=yes,width=600,height=700');
      // loadSite resolves immediately — we can't detect popup load in browser mode,
      // so hide the connecting spinner right away.
      task.loadSite.resolve('load_success');
      setupInAppBrowserListeners(ref, task.loadToken, task.loadSite, task.exitSite);
    } else if (isMobile) {
      // On device: open the system browser so Android can handle the iomaintenance://
      // redirect as a deep link (via cordova-plugin-customurlscheme → handleOpenURL).
      oaLog.debug('OAuth.login', 'Mobile: opening system browser for OAuth.');
      var openSystemBrowser = (window.cordova && window.cordova.InAppBrowser)
        ? window.cordova.InAppBrowser.open.bind(window.cordova.InAppBrowser)
        : window.open.bind(window);
      openSystemBrowser(url, '_system');
      setTimeout(function() { task.loadSite.resolve('browser_opened'); }, 500);
      setupSystemBrowserListeners(task.loadToken, task.exitSite);
    } else {
      $http({
        method: 'GET',
        url: url
      }).then(function() {
        oaLog.debug('OAuth.login', 'Site is active. Attempting login.');
        throw 'Desktop implementation not yet done.';
      }, function(response) {
        oaLog.debug('OAuth.login', 'Failed to load the host site.');
        task.loadSite.reject(response);
        task.loadToken.reject();
        task.exitSite.reject();
      });
    }

    return {
      loadSite: task.loadSite.promise,
      loadToken: task.loadToken.promise,
      exitSite: task.exitSite.promise
    };
  }

  /**
   * Retrieve the current host providing the methods for the oauth
   * flow.
   */
  function getHostService() {
    oaHost.loadHost();
    return hostMap[oaHost.name];
  }


  /**
   * Submit a request to be executed. The request has to be a function
   * without parameters which returns a promise. A name must be
   * provided along with the function so that we may identify the
   * request.
   *
   * Note that this function acts as a safety wrapper to check first
   * if a request is in progress. If it is still in progress then
   * there is no need to submit another one. The promise from the
   * submitted request is returned. Otherwise a new request is made.
   *
   * @param {String} name A name to identify the request.
   * @param {Function} func Any function without parameters which
   *                        returns a promise.
   *
   * @returns {Promise} The promise from the request.
   */
  function submitRequest(name, func) {
    if (!inProgress.hasOwnProperty(name)) {
      inProgress[name] = null;
    }
    if (inProgress[name] === null) {
      oaLog.debug('OAuth::submitRequest', 'Submitting a request -> ' + name);
      inProgress[name] = func();
      inProgress[name]['finally'](function() {
        inProgress[name] = null;
      });
    } else {
      oaLog.warn('OAuth::submitRequest', 'Request already in progress -> ' + name);
    }
    return inProgress[name];
  }


  /**
   * Returns true if a token is available. Note that the token may
   * not necessarily be valid. Use the method `hasAccess` to to
   * check if the token is valid.
   *
   * @returns {Boolean} true if there is a token
   */
  function hasToken() {
    if ('oauth-dev' in window.localStorage) {
      return true; // Bypass OAuth
    }
    return (oaToken.loadToken() ? true : false);
  }


  /**
   * Lets the module know that the user has no access to the host
   * using the current token. Thus, the token will be deleted.
   *
   * @param {String} reason The reason why there is no access.
   * @returns {Object} An object with the status set to false and
   *                   a reason set to the one provided.
   */
  function accessDenied(reason) {
    oaLog.debug('OAuth', 'Access was denied => ' + reason);
    if (hasToken()) {
      if (reason.indexOf("access_denied") !== 0) {
        oaLog.debug('OAuth', 'The token may exist in the server, attempting to logout. ');
        logout();
      }
      oaToken.clearToken();
    }
    return {
      status: false,
      reason: reason
    };
  }


  /**
   * Lets the module know that the user is allowed to access the host
   * resources. You may provide the token which gives the access.
   * Otherwise, if the token is already set then use no arguments.
   *
   * @param {Object} [data] Token object which grants access.
   * @returns {Object} An object with status set to true and a reason.
   */
  function accessAllowed(data) {
    if (data) {
      oaToken.storeToken(data);
      oaLog.debug('OAuth', data.expires_in +' seconds of access with the token ' + data.access_token);
    } else {
      oaLog.debug('OAuth', 'Access was granted. No data was provided.');
    }
    return {
      status: true,
      reason: 'access granted'
    };
  }


  /**
   * Lets the module know that the user does not have access due to
   * the host not being available. i.e. the host returns status code
   * 0 or no data. This is different from accessDenied since this
   * will not remove the token.
   *
   * We also have to use the parameter location which will let us know
   * the function called that determined that the access was not
   * available.
   *
   * @returns {Object} An object with status set to false and a reason
   *                   set to 'host_offline'
   */
  function accessUnavailable(location) {
    oaLog.debug('OAuth', 'Access is unavailable -> ' + location);

    if (typeof getHostService().onAccessDenied === 'function') {
      getHostService().onAccessDenied("host_offline", location);
    }

    return {
      status: false,
      reason: 'host_offline'
    };
  }


  /**
   * Returns a promise to inform us if the user has access to the
   * server. The result will always be an object with the attributes
   * `status` and `reason`. The first property will specify if the
   * user has access (true or false). The second one may be a
   * string specifying the reason why the user has no access.
   *
   * TODO: To be completed. Disregard for time being.
   *
   * @returns {Promise}
   */
  function hasAccess() {
    oaLog.debug('OAuth::hasAccess', 'hasAccess() has been called.');
    if (hasToken()) {
      oaLog.debug('OAuth::hasAccess', 'Allowing access without verification.');
      return $q.when(accessAllowed());
    }
    var hash = oaHash.get();
    if (hash && hash.code) {
      oaLog.debug('OAuth::hasAccess', 'Wait while a token is requested with the code: ' + hash.code + '.');
      return requestToken(hash.code);
    }
    oaLog.debug('OAuth::hasAccess', 'There is no token, thus no access.');
    return $q.when(accessDenied('missing_token'));
  }


  /**
   * Obtain the access token. Returns null if it doesn't exist.
   *
   * @returns {String} The access token.
   */
  function getAccessToken() {
    oaToken.loadToken();
    return oaToken.accessToken;
  }


  /**
   * Obtain the refresh token. Returns null if it doesn't exist.
   *
   * @returns {String} The access token.
   */
  function getRefreshToken() {
    oaToken.loadToken();
    return oaToken.refreshToken;
  }

  /**
   * Obtain the host site.
   *
   * @returns {String} The host site, empty string if not set.
   */
  function getHostSite() {
    return oaHost.loadHost() ? oaHost.site : '';
  }

  /**
   * Wrapper function to call host's `requestToken` function.
   *
   * @param code The authorization code.
   * @returns {Promise}
   */
  function requestToken(code) {
    return submitRequest('OAuth.requestToken', function() {
      return getHostService().requestToken(code);
    });
  }


  /**
   * Wrapper function to call the host's `refreshToken` function.
   *
   * @returns {Promise}
   */
  function refreshToken() {
    return submitRequest('OAuth.refreshToken', function() {
      return getHostService().refreshToken(getRefreshToken());
    });
  }


  /**
   * Wrapper function to call the host's `verifyToken` function.
   *
   * @returns {Promise}
   */
  function verifyToken() {
    return submitRequest('OAuth.verifyToken', function() {
      return getHostService().verifyToken(getAccessToken());
    });
  }


  /**
   * Wrapper function to call the host's `logout` function.
   *
   * @returns {Promise}
   */
  function logout() {
    return submitRequest('OAuth.logout', function() {
      var accessToken = getAccessToken(),
        hostService = getHostService();
      oaToken.clearToken();
      if (hostService) {
        return hostService.logout(accessToken);
      }
    });
  }


  /**
   * This function may be called when the client has no access to
   * the server. It calls the host onAccessDenied.
   *
   * @param {String} reason The reason why the access was denied.
   */
  function onAccessDenied(reason) {
    accessDenied(reason);
    if (typeof getHostService().onAccessDenied == 'function') {
      getHostService().onAccessDenied(reason);
    }
  }


  /**
   * If the http headers are already available you may call
   * this function to update them to provide you with access.
   *
   * @param {Object} header The http header object.
   */
  function setAccessHeaders(header) {
    return angular.extend(header, getHostService().getAccessHeaders());
  }


  /**
   * Check if the error response states that the error was due to
   * bad credentials, that is, the host does not recognize you and it
   * will not give you access with the current token.
   *
   * @param response The error response.
   * @returns {*}
   */
  function badCredentials(response) {
    var host = getHostService();
    if (host.hasOwnProperty('badCredentials')) {
      return host.badCredentials(response);
    }
    return (response.status == 401);
  }


  /**
   * Check if the error response states that the error was due to
   * an expired token.
   *
   * @param response The error response.
   * @returns {*}
   */
  function mayRefresh(response) {
    var host = getHostService();
    if (host.hasOwnProperty('mayRefresh')) {
      return host.mayRefresh(response);
    }
    return (response.status == 403);
  }

}

angular.module('oauth')
  .factory('OAuth', [
    'oaToken',
    'oaHost',
    'oaHash',
    'oaLog',
    '$q',
    '$http',
    OAuth
  ]);

angular.module('oauth')
    .factory('oaHash', ['$location', oaHash]);

/**
 * The `oaHash` service provides functions to parse and compose query
 * parameters. These are used in combination with the `$location`
 * service to obtain the hash parameters in the application.
 */
function oaHash($location) {
  return {
    get: get,
    set: set,
    del: del,
    extend: extend,
    parse: parse,
    compose: compose
  };

  /**
   * Returns an object containing the hash parameters specified in
   * the current url.
   *
   * @returns {Object} A parameters if any, otherwise null.
   */
  function get() {
    return parse($location.hash());
  }


  /**
   * Sets the hash parameters in the current location from an object.
   * For instance, calling `oauth.set({a: 1, b: 2})` will make the
   * next call for `$location.hash()` return `a=1&b=2`.
   *
   * @param {Object} query The object with the query parameters.
   * @returns {Object} The object parameter.
   */
  function set(query) {
    $location.hash(compose(query));
    return query;
  }

  /**
   * Deletes parameters by name.
   *
   * @param {...String} [arguments] keys/properties to be deleted.
   * @returns {Object} The new parameters in the hash.
   */
  function del() {
    var params = get() || {};
    for (var i = 0, ii = arguments.length; i < ii; i++) {
      delete params[arguments[i]];
    }
    return set(params);
  }


  /**
   * Extends the hash parameters by copying properties from the
   * given parameter(s).
   *
   * @param {...String} [arguments] object(s).
   * @returns {Object} The new parameters in the hash.
   */
  function extend() {
    var args = Array.prototype.slice.call(arguments);  // Get arguments as array
    args.unshift(get() || {});                         // Prepend current parameters
    return set(angular.extend.apply(this, args));
  }

  /**
   * Parses a string in the form `a=1&b=2...` and builds an object
   * from the parsed information. If the object to be returned is
   * empty then the returned value will be null. If you must
   * always obtain an object you may do
   *
   * `oaHash.parse(query) || {}`.
   *
   * Note: Checking if the result is null informs us quickly that the
   * query was empty. No need to check if the object has properties.
   *
   * @param {String} query The uri query string parameters.
   * @returns {Object} The parameters if any, otherwise null.
   */
  function parse(query) {
    var pair, result = {},
        empty = true,
        vars = query.split('&');
    for (var i = 0; i < vars.length; i++) {
      pair = vars[i].split('=');
      if (pair[0] !== '') {
        empty = false;
        result[pair[0]] = decodeURIComponent(pair[1]);
      }
    }
    return (empty ? null : result);
  }

  /**
   * Generates a string in the form of uri query parameters.
   * For instance, the object `{a: 1, b: 2}` will generate
   * the string `a=1&b=2`.
   *
   * @param {Object} query The object with the parameters.
   * @returns {String} A valid URI query parameters string.
   */
  function compose(query) {
    return Object.keys(query).map(function(value) {
      return value + "=" + encodeURIComponent(query[value]);
    }).join('&');
  }

}

angular.module('oauth')
    .factory('oaHost', ['oaHash', 'oaLog', oaHost]);

/**
 * Service to set and access the information of the host providing the
 * access tokens.
 */
function oaHost(oaHash, oaLog) {

  var host = null;
  var required = [
    'host',
    'site',
    'clientId',
    'redirectUri',
    'authorizePath'
  ];
  var optional = {
    'clientSecret': '',
    'scope': '',
    'state': ''
  };
  var service = {
    name: '',
    site: '',
    clientId: '',
    redirectUri: '',
    authorizedPath: '',
    clientSecret: '',
    scope: '',
    state: '',

    loadHost: loadHost,
    storeHost: storeHost,
    clearHost: clearHost,
    composeAuthPath: composeAuthPath,
    composeAPIPath: composeAPIPath

    //Exposed only for testing purposes
    //,createHost: createHost
  };
  return service;


  /**
   * Retrieves the host object. If no host is set then it attempts
   * to set it. Returns null if no host is found.
   *
   * @returns {Object} The host object.
   */
  function loadHost() {
    return host || storeHost();
  }


  /**
   * Sets and returns the host object. It tries the following:
   * - takes the host from the function parameter (if given)
   * - takes the host from the local storage.
   *
   * @param {Object} [hostObj] The host object to store.
   * @returns {Object} The host object.
   */
  function storeHost(hostObj) {
    var obj = null,
        inStorage = false;
    if (hostObj) {
      obj = createHost(hostObj);
    } else if ('oauth-host' in window.localStorage) {
      obj = createHost(JSON.parse(window.localStorage['oauth-host']));
      if (obj) {
        inStorage = true;
      }
    }
    host = obj;
    if (host) {
      if (!inStorage) {
        oaLog.debug('oaHost::storeHost', 'Storing ' + host.host + ' host');
        window.localStorage['oauth-host'] = JSON.stringify(host);
      }
      service.name = host.host;
      service.site = host.site;
      service.clientId = host.clientId;
      service.redirectUri = host.redirectUri;
      service.authorizedPath = host.authorizedPath;
      service.clientSecret = host.clientSecret;
      service.scope = host.scope;
      service.state = host.state;
    } else {
      clearHost();
    }
    return host;
  }


	/**
	 * Removes the host from storage.
	 */
	function clearHost() {
    service.name = '';
    service.site = '';
    service.clientId = '';
    service.redirectUri = '';
    service.authorizedPath = '';
    service.clientSecret = '';
    service.scope = '';
    service.state = '';
		delete window.localStorage['oauth-host'];
		host = null;
	}


  /**
   * Composes the url where the user authorization takes place. The
   * default query parameters may be overwritten by passing the input
   * parameter. By default the authorization path will have the
   * following query parameters:
   *
   *  - client_id
   *  - redirect_uri
   *  - scope
   *  - response_type
   *  - state
   *
   * Each of their values depends on how the host was configured, with
   * the exception of "response_type" which defaults to 'code'.
   *
   * @returns {String} The authorization url.
   */
  function composeAuthPath(params) {
    var queryParams = {
      client_id: host.clientId,
      redirect_uri: host.redirectUri,
      scope: host.scope,
      response_type: 'code',
      state: host.state
    };
    angular.extend(queryParams, params);
    return composeAPIPath(host.authorizePath, queryParams);
  }


  /**
   * Composes a url with the `site`s host object property as its base
   * path. Returns null if the host has not been set.
   *
   * @returns {String} The composed path.
   */
  function composeAPIPath(endpoint, params) {
    if (host) {
      params = params || {};
      var authPathHasQuery = (host.authorizePath.indexOf('?') != -1),
          appendChar = (authPathHasQuery) ? '&' : '?',
          queryParams = oaHash.compose(params),
          path = host.site + endpoint;
      if (queryParams) {
        path += appendChar + queryParams;
      }
      return path;
    }
    return null;
  }


  /**
   * Creates a new object with all the required fields for a valid
   * host. Some fields are optional and will default to an empty
   * string in the case they are not provided. If the required fields
   * are not present the function will return null.
   *
   * Required fields:
   * - host
   * - site
   * - clientId
   * - redirectUri
   * - authorizePath
   *
   * Optional:
   * - clientSecret
   * - scope
   * - state
   *
   * @param {Object} params Object with the token parameters.
   * @returns {Object} The host object
   */
  function createHost(params) {
    if (!hasAttributes(params, required)) {
      return null;
    }
    return _.defaults(params, optional);
  }

}

angular.module('oauth')
    .factory('oaLog', ['$log', oaLog]);

/**
 * Wrapper around the $log service to handle log messages related
 * to the oauth flow.
 *
 * Example:
 *
 *     oaLog.turnOff();
 *     oaLog.info("testing_context", "this message will not print");
 *
 *     oaLog.turnOn();
 *     oaLog.info("testing_context", "this message will print");
 *
 *     oaLog.disableContext("testing_context");
 *     oaLog.info("testing_context", "will not print");
 *     oaLog.info("other_context", "this will print");
 *
 */
function oaLog($log) {

  var disabled = true,
      contextDisabled = {};

  return {
    turnOff: turnOff,
    turnOn: turnOn,
    enableContext: enableContext,
    disableContext: disableContext,
    log: wrapLog($log.log),
    info: wrapLog($log.info),
    warn: wrapLog($log.warn),
    error: wrapLog($log.error),
    debug: wrapLog($log.debug)
  };

  /**
   * @private
   *
   * Wraps the log function so that a message may be printed when
   * `disabled` is set to false and the specified context is
   * enabled.
   */
  function wrapLog(log) {
    return function(context, msg) {
      if (!disabled && !contextDisabled[context]) {
        log('[' + context + ']: ' + msg);
      }
    };
  }

  /**
   * Disable all messages printed by the oaLog service.
   */
  function turnOff() {
    disabled = true;
  }

  /**
   * Enable the oaLog messages. Some messages may not be displayed if
   * a given context has been disabled.
   */
  function turnOn() {
    disabled = false;
  }

  /**
   * Enable a context so that when it is encountered the message may
   * be printed.
   */
  function enableContext(context) {
    contextDisabled[context] = false;
  }

  /**
   * Disable a context so that messages under that context are not
   * displayed.
   */
  function disableContext(context) {
    contextDisabled[context] = true;
  }

}

angular.module('oauth')
    .factory('oaToken', ['oaHash', 'oaLog', oaToken]);


/**
 * The `oaToken` service provides functions to storeToken and access an oauth
 * token. Note that there is only one token per session. This token
 * may be stored indefinitely in the local storage.
 */
function oaToken(oaHash, oaLog) {

  var token = null;
  var required = [
    'token_type', 'access_token', 'expires_in'
  ];
  var optional = {
    'expires_at': null,
    'refresh_token': '',
    'scope': '',
    'state': ''
  };
  var service = {
    accessToken: '',
    refreshToken: '',

    loadToken: loadToken,
    storeToken: storeToken,
    clearToken: clearToken,
    isExpired: isExpired

    //Exposed only for testing purposes.
    //,createToken: createToken,
    //extractHash: extractHash
  };
  return service;

  /**
   * Retrieve the underlying token object. This object contains the
   * following keys:
   *
   *  token_type
   *  access_token
   *  expires_in
   *  expires_at
   *  refresh_token
   *  scope
   *  state
   *
   * This is all the information retrieved from the host. You may
   * however, want to use the services' variables
   *
   *  accessToken
   *  refreshToken
   *
   * These variables will always be updated after every call to
   * this function, so make sure to call it.
   *
   * @returns {Object} The token object.
   */
  function loadToken() {
    return token || storeToken();
  }

  /**
   * Sets and returns the token object. It tries the following:
   * - takes the token from the uri parameters
   * - takes the token from the function parameter (if given)
   * - takes the token from the local storage.
   *
   * @param {Object} [tokenObj] The token object to store.
   * @returns {Object} The token object.
   */
  function storeToken(tokenObj) {
    var obj = extractHash(),
        inStorage = false;
    if (obj === null) {
      if (tokenObj) {
        obj = createToken(tokenObj);
      } else if ('oauth-token' in window.localStorage) {
        var storedObj = JSON.parse(window.localStorage['oauth-token']);
        obj = createToken(storedObj);
        if (obj) {
          inStorage = true;
        }
      }
    }
    token = obj;
    if (token) {
      if (!inStorage) {
        oaLog.debug('oaToken::storeToken', 'Storing token ' + token.access_token + ' <-> ' + token.expires_in + ' sec');
        window.localStorage['oauth-token'] = JSON.stringify(token);
      }
      service.accessToken = token.access_token;
      service.refreshToken = token.refresh_token;
    } else {
      clearToken();
    }
    return token;
  }

  /**
   * Deletes the token object.
   */
  function clearToken() {
    service.accessToken = '';
    service.refreshToken = '';
    delete window.localStorage['oauth-token'];
    token = null;
  }

  /**
   * Check if the token object has reached its expiration date. May
   * also return true if there is no token.
   *
   * @returns {Boolean} true if expired.
   */
  function isExpired() {
    return ((token === null) || (token.expires_at < new Date()));
  }

  /**
   * Creates a new object with all the required fields for a valid
   * token. Some fields are optional. If the required fields are not
   * present the function will return null.
   *
   * Required properties:
   * - token_type
   * - access_token
   * - expires_in
   *
   * Optional:
   * - expires_at
   * - refresh_token
   * - scope
   * - state
   *
   * Note: When passing the `expires_at` property make sure that
   *       it is a valid date object.
   *
   * @param {Object} params Object with the token parameters.
   * @returns {Object} The token object
   */
  function createToken(params) {
    if (!hasAttributes(params, required)) {
      return null;
    }
    var obj = _.defaults(params, optional);
    return setExpirationDate(obj);
  }

  /**
   * Read the hash parameters. If the required parameters to create
   * a token are found then all the possible parameters to create a
   * token will be removed from the location hash, and new token will
   * be returned. Otherwise the location hash is left untouched
   * and the function will return null.
   *
   * @returns {Object} A valid token or null.
   */
  function extractHash() {
    var query = oaHash.get();
    var obj = createToken(query);
    if (obj) {
      oaLog.debug('oaToken::extractHash', 'Token was found in url');
      // The following line will change the hash and the page will reload.
      oaHash.del.apply(this, required.concat(_.keys(optional)));
    }
    return obj;
  }

  /**
   * Set the expiration date on the input object. Note that
   * the input should have the attribute `expires_in` and optionally
   * `expires_at`.
   *
   * @param {Object} obj The object to modify.
   * @returns {*}
   */
  function setExpirationDate(obj) {
    if (obj.expires_at) {
      obj.expires_at = new Date(obj.expires_at);
    } else {
      var expires_at = new Date(),
          seconds = expires_at.getSeconds() + parseInt(obj.expires_in);
      expires_at.setSeconds(seconds);
      obj.expires_at = expires_at;
    }
    return obj;
  }

}

})();
