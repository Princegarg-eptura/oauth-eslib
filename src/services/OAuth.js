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
