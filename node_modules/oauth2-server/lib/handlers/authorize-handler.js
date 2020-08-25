'use strict';

/**
 * Module dependencies.
 */

var _ = require('lodash');
var AccessDeniedError = require('../errors/access-denied-error');
var AuthenticateHandler = require('../handlers/authenticate-handler');
var TokenHandler = require('../handlers/token-handler');
var TokenModel = require('../models/token-model');
var BearerTokenType = require('../token-types/bearer-token-type');
var InvalidArgumentError = require('../errors/invalid-argument-error');
var InvalidClientError = require('../errors/invalid-client-error');
var InvalidRequestError = require('../errors/invalid-request-error');
var InvalidScopeError = require('../errors/invalid-scope-error');
var UnsupportedResponseTypeError = require('../errors/unsupported-response-type-error');
var OAuthError = require('../errors/oauth-error');
var Promise = require('bluebird');
var promisify = require('promisify-any').use(Promise);
var Request = require('../request');
var Response = require('../response');
var ServerError = require('../errors/server-error');
var UnauthorizedClientError = require('../errors/unauthorized-client-error');
var is = require('../validator/is');
var tokenUtil = require('../utils/token-util');
var url = require('url');
var debug = require('debug')('oauth2-server: authorize-handler')


/**
 * Grant Types
 */

var grantTypes = {
  authorization_code: require('../grant-types/authorization-code-grant-type'),
  implicit: require('../grant-types/implicit-grant-type'),
  hybrid: require('../grant-types/hybrid-grant-type'),
};

/**
 * Response types.
 */

var responseTypes = {
  code: require('../response-types/code-response-type'),
  token: require('../response-types/token-response-type'),
  id_token : require('../response-types/id-token-response-type'),
  id_token_token : require('../response-types/id-token-token-response-type'),
  code_id_token : require('../response-types/code-id-token-response-type'),
  code_token : require('../response-types/code-token-response-type'),
  code_id_token_token : require('../response-types/code-id-token-token-response-type'),
  none : require('../response-types/none-response-type')
};

/**
 * Constructor.
 */

function AuthorizeHandler(options) {
  options = options || {};
  if (options.authenticateHandler && !options.authenticateHandler.handle) {
    throw new InvalidArgumentError('Invalid argument: authenticateHandler does not implement `handle()`');
  }

  if (!options.authorizationCodeLifetime) {
    throw new InvalidArgumentError('Missing parameter: `authorizationCodeLifetime`');
  }

  if (!options.accessTokenLifetime) {
    throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
  }

  if (!options.model) {
    throw new InvalidArgumentError('Missing parameter: `model`');
  }

  if (!options.model.getClient) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
  }

  if (!options.model.saveAuthorizationCode) {
    throw new InvalidArgumentError('Invalid argument: model does not implement `saveAuthorizationCode()`');
  }

  this.allowEmptyState = options.allowEmptyState;
  this.authenticateHandler = options.authenticateHandler || new AuthenticateHandler(options);
  this.authorizationCodeLifetime = options.authorizationCodeLifetime;
  this.accessTokenLifetime = options.accessTokenLifetime;
  this.model = options.model;
}

/**
 * Authorize Handler.
 */

AuthorizeHandler.prototype.handle = function(request, response) {
  debug("======AuthorizeHandler: AuthzHandle======")
  if (!(request instanceof Request)) {
    throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
  }

  if (!(response instanceof Response)) {
    throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
  }

  if ('false' === request.query.allowed) {
    return Promise.reject(new AccessDeniedError('Access denied: user denied access to application'));
  }


  var ResponseType = this.getResponseType(request);

  if (ResponseType === 'code') {
    return this.handleCodeResponseType(request, response)
  } else if (ResponseType === 'token') {
    return this.handleTokenResponseType(request, response)
  } else if (ResponseType === 'id_token') {
    return this.handleIDTokenResponseType(request, response)
  } else if (ResponseType === 'id_token_token') {
    return this.handleIDTokenTokenResponseType(request, response)
  } else if (ResponseType === 'code_id_token') {
    return this.handleCodeIDTokenResponseType(request, response)
  } else if (ResponseType === 'code_token') {
    return this.handleCodeTokenResponseType(request, response)
  } else if (ResponseType === 'code_id_token_token') {
    return this.handleCodeIDTokenTokenResponseType(request, response)
  } else {
    return this.handleNoneResponseType(request, response)
  }
};

/**
 * Get response type.
 */

AuthorizeHandler.prototype.getResponseType = function(request) {
  debug("======AuthorizeHandler: getResponseType======")
  var responseType = request.body.response_type || request.query.response_type;

  if (!responseType) {
    throw new InvalidRequestError('Missing parameter: `response_type`');
  }

  let responseTypeTemp = responseType.split(' ').sort().join(' ').replace(/ /g, "_");

  if (!_.has(responseTypes, responseTypeTemp)) {
    throw new UnsupportedResponseTypeError('Unsupported response type: `response_type` is not supported');
  }

  return responseTypeTemp
};


/**
 * Handle authorization code response type.
 */

AuthorizeHandler.prototype.handleCodeResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleCodeResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['code']

  return Promise.all(fns).bind(this).spread(function(client, user) {
    var uri = this.getRedirectUri(request, client);
    var extended_query_parameters = this.getExtendedParameters(request);
    var expiresAt = this.getAuthorizationCodeLifetime(client);
    var scope;
    var state;

    return Promise.bind(this).then(function() {
      scope = this.getScope(request);
      return this.generateAuthorizationCode(client, user, scope);
    }).then(function(authorizationCode) {
        state = this.getState(request);
        return this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);
    }).then(function(code) {
        var responseType = new ResponseType(code.authorizationCode);
        var redirectUri = this.buildSuccessRedirectUri(uri, responseType);
        //En la vuelta no tiene que ir Scope
        //Comprobar que no estan en los extended parameters
        return this.updateResponse(response, redirectUri, state, extended_query_parameters);
        //return code;
    }).catch(function(e) {
      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }
      var redirectUri = this.buildErrorRedirectUri(uri, e);

      this.updateResponse(response, redirectUri, state, extended_query_parameters);

      throw e;
    });
  });

};

/**
 * Handle authorization id_token response type.
 */

AuthorizeHandler.prototype.handleIDTokenResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleIDTokenResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['id_token']
  //debug("**REQUEST.QUERY***" + request.query)

  return Promise.all(fns).bind(this).spread(function(client, user) {
    var uri = this.getRedirectUri(request, client);
    var extended_query_parameters = this.getExtendedParameters(request);
    var idTokenLifetime = this.getIDTokenLifetime(client);
    var state;
    var scope;

    return Promise.bind(this).then(function() {
      scope = this.getScope(request);
      return scope;
    }).then(function(scope) {
      var options = {
        idTokenLifetime: idTokenLifetime,
        model: this.model
      };
      return new grantTypes.implicit(options).handle(request, client, user, scope);

    }).then(function(id_token) {
        state = this.getState(request);
        var responseType = new ResponseType(id_token);
        var redirectUri = this.buildSuccessRedirectUri(uri, responseType);
        return this.updateResponse(response, redirectUri, state, extended_query_parameters);

        //return token;
    }).catch(function(e) {

      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }
      var redirectUri = this.buildErrorRedirectUri(uri, e);

      this.updateResponse(response, redirectUri, state, extended_query_parameters);

      throw e;
    });
  });
}

/**
 * Handle authorization id_token_token response type.
 */

AuthorizeHandler.prototype.handleIDTokenTokenResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleIDTokenTokenResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['id_token_token']

  return Promise.all(fns).bind(this).spread(function(client, user) {
    var uri = this.getRedirectUri(request, client);
    var extended_query_parameters = this.getExtendedParameters(request);
    var idTokenLifetime = this.getIDTokenLifetime(client);
    var accessTokenLifetime = this.getAccessTokenLifetime(client);
    var state;
    var scope;

    return Promise.bind(this).then(function() {
      scope = this.getScope(request);
      return scope;
    }).then(function(scope) {
      var options = {
        idTokenLifetime: idTokenLifetime,
        accessTokenLifetime: accessTokenLifetime,
        model: this.model
      };
      return new grantTypes.implicit(options).handle(request, client, user, scope);

    }).then(function(id_token_token) {
        state = this.getState(request);
        var responseType = new ResponseType(id_token_token);
        var redirectUri = this.buildSuccessRedirectUri(uri, responseType);
        return this.updateResponse(response, redirectUri, state, extended_query_parameters);

        //return token;
    }).catch(function(e) {

      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }
      var redirectUri = this.buildErrorRedirectUri(uri, e);

      this.updateResponse(response, redirectUri, state, extended_query_parameters);

      throw e;
    });
  });
}

/**
 * Handle authorization code_id_token response type.
 */

AuthorizeHandler.prototype.handleCodeIDTokenResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleCodeIDTokenResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['code_id_token']

  return Promise.all(fns).bind(this).spread(function(client, user) {
    var uri = this.getRedirectUri(request, client);
    var extended_query_parameters = this.getExtendedParameters(request);
    var idTokenLifetime = this.getIDTokenLifetime(client);
    var expiresAt = this.getAuthorizationCodeLifetime(client);
    var state;
    var scope;
    var code_idToken;
    var authCode;

    return Promise.bind(this).then(function() {
      scope = this.getScope(request);
      return this.generateAuthorizationCode(client, user, scope);
    }).then(function(authorizationCode) {
        state = this.getState(request);
        return this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);
    }).then(function(code){
      authCode = code.authorizationCode;
      var options = {
        idTokenLifetime: idTokenLifetime,
        model: this.model
      };
      return new grantTypes.hybrid(options).handleAuthorization(request, client, user, scope, authCode);

    }).then(function(code_id_token) {
        state = this.getState(request);

        var responseType = new ResponseType(authCode, code_id_token);
        var redirectUri = this.buildSuccessRedirectUri(uri, responseType);
        return this.updateResponse(response, redirectUri, state, extended_query_parameters);

    }).catch(function(e) {

      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }
      var redirectUri = this.buildErrorRedirectUri(uri, e);

      this.updateResponse(response, redirectUri, state, extended_query_parameters);

      throw e;
    });
  });
}

/**
 * Handle authorization code_token response type.
 */

AuthorizeHandler.prototype.handleCodeTokenResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleCodeTokenResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['code_token']

  return Promise.all(fns).bind(this).spread(function(client, user) {
    var uri = this.getRedirectUri(request, client);
    var extended_query_parameters = this.getExtendedParameters(request);
    var accessTokenLifetime = this.getAccessTokenLifetime(client);
    var expiresAt = this.getAuthorizationCodeLifetime(client);
    var state;
    var scope;
    var token;
    var authCode;

    return Promise.bind(this).then(function() {
      scope = this.getScope(request);
      return this.generateAuthorizationCode(client, user, scope);
    }).then(function(authorizationCode) {
        state = this.getState(request);
        return this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);
    }).then(function(code) {
      authCode = code.authorizationCode;
      debug("AUTH CODE")
      debug(authCode)
      var options = {
        accessTokenLifetime: accessTokenLifetime,
        model: this.model
      };
      return new grantTypes.hybrid(options).handleAuthorization(request, client, user, scope, authCode);

    }).then(function(code_token) {
        state = this.getState(request);
        debug("CODE_TOKEN")
        debug(code_token)

      var responseType = new ResponseType(authCode, code_token);
      var redirectUri = this.buildSuccessRedirectUri(uri, responseType);
      return this.updateResponse(response, redirectUri, state, extended_query_parameters);
    }).catch(function(e) {

      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }
      var redirectUri = this.buildErrorRedirectUri(uri, e);

      this.updateResponse(response, redirectUri, state, extended_query_parameters);

      throw e;
    });
  });
}

/**
 * Handle authorization code_id_token_token response type.
 */

AuthorizeHandler.prototype.handleCodeIDTokenTokenResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleCodeIDTokenTokenResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['code_id_token_token']

  return Promise.all(fns).bind(this).spread(function(client, user) {
    var uri = this.getRedirectUri(request, client);
    var extended_query_parameters = this.getExtendedParameters(request);
    var accessTokenLifetime = this.getAccessTokenLifetime(client);
    var idTokenLifetime = this.getIDTokenLifetime(client);
    var expiresAt = this.getAuthorizationCodeLifetime(client);
    var state;
    var scope;
    var token;
    var id_token;
    var authCode;

    return Promise.bind(this).then(function() {
      scope = this.getScope(request);
      return this.generateAuthorizationCode(client, user, scope);
    }).then(function(authorizationCode) {
        state = this.getState(request);
        return this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);
    }).then(function(code) {
      authCode = code.authorizationCode;
      debug("AUTH CODE")
      debug(authCode)
      var options = {
        accessTokenLifetime: accessTokenLifetime,
        idTokenLifetime: idTokenLifetime,
        model: this.model
      };
      return new grantTypes.hybrid(options).handleAuthorization(request, client, user, scope, authCode);

    }).then(function(code_id_token_token) {
      state = this.getState(request);
      debug("CODE_ID_TOKEN_TOKEN")
      debug(code_id_token_token)

      var responseType = new ResponseType(authCode, code_id_token_token);
      var redirectUri = this.buildSuccessRedirectUri(uri, responseType);
      return this.updateResponse(response, redirectUri, state, extended_query_parameters);
      //return token;
    }).catch(function(e) {

      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }
      var redirectUri = this.buildErrorRedirectUri(uri, e);

      this.updateResponse(response, redirectUri, state, extended_query_parameters);

      throw e;
    });
  });
}

/**
 * Handle authorization none response type.
 */

AuthorizeHandler.prototype.handleNoneResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleNoneResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['none']
}

/**
 * Handle authorization token response type.
 */

AuthorizeHandler.prototype.handleTokenResponseType = function(request, response) {
  debug("======AuthorizeHandler: handleTokenResponseType======")

  var fns = [
    this.getClient(request),
    this.getUser(request, response)
  ];

  var ResponseType = responseTypes['token']

  return Promise.all(fns).bind(this).spread(function(client, user) {
    var uri = this.getRedirectUri(request, client);
    var extended_query_parameters = this.getExtendedParameters(request);
    var accessTokenLifetime = this.getAccessTokenLifetime(client);
    var state;
    var scope;

    return Promise.bind(this).then(function() {
      scope = this.getScope(request);
      return scope;
    }).then(function(scope) {
      var options = {
        accessTokenLifetime: accessTokenLifetime,
        model: this.model
      };
      return new grantTypes.implicit(options).handle(request, client, user, scope);

    }).then(function(token) {
        state = this.getState(request);
        var responseType = new ResponseType(token);
        var redirectUri = this.buildSuccessRedirectUri(uri, responseType);
        return this.updateResponse(response, redirectUri, state, extended_query_parameters);

        //return token;
    }).catch(function(e) {

      if (!(e instanceof OAuthError)) {
        e = new ServerError(e);
      }
      var redirectUri = this.buildErrorRedirectUri(uri, e);

      this.updateResponse(response, redirectUri, state, extended_query_parameters);

      throw e;
    });
  });

};


/**
 * Generate authorization code.
 */

AuthorizeHandler.prototype.generateAuthorizationCode = function(client, user, scope) {
  debug("======AuthorizeHandler: GenAuthzCOde======")
  if (this.model.generateAuthorizationCode) {
    return promisify(this.model.generateAuthorizationCode).call(this.model, client, user, scope);
  }
  return tokenUtil.generateRandomToken();
};

/**
 * Get authorization code lifetime.
 */

AuthorizeHandler.prototype.getAuthorizationCodeLifetime = function(client) {
  debug("======AuthorizeHandler: GenAuthCodeLife======")

  var auth_code_lifetime = client.authorizationCodeLifetime || this.authorizationCodeLifetime;
  var expires = new Date();

  expires.setSeconds(expires.getSeconds() + auth_code_lifetime);
  return expires;
};

/**
 * Get the client from the model.
 */

AuthorizeHandler.prototype.getClient = function(request) {
  debug("======AuthorizeHandler: getClie======")
  var clientId = request.body.client_id || request.query.client_id;

  if (!clientId) {
    throw new InvalidRequestError('Missing parameter: `client_id`');
  }

  if (!is.vschar(clientId)) {
    throw new InvalidRequestError('Invalid parameter: `client_id`');
  }

  var redirectUri = request.body.redirect_uri || request.query.redirect_uri;

  if (redirectUri && !is.uri(redirectUri)) {
    throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
  }
  return promisify(this.model.getClient, 2).call(this.model, clientId, null)
    .then(function(client) {
      if (!client) {
        throw new InvalidClientError('Invalid client: client credentials are invalid');
      }

      if (!client.grants) {
        throw new InvalidClientError('Invalid client: missing client `grants`');
      }

      let responseTypeTemp = request.query.response_type.split(' ');


      if (responseTypeTemp.includes('code') && !_.includes(client.grants, 'authorization_code')) {
        throw new UnauthorizedClientError('Unsupported grant type: `grant_type` is invalid');
      }

      if (responseTypeTemp.includes('token') && !_.includes(client.grants, 'implicit')) {
        throw new UnauthorizedClientError('Unsupported grant type: `grant_type` is invalid');
      }

      if (responseTypeTemp.includes('id_token') && !_.includes(client.response_types, 'id_token')) {
        throw new UnauthorizedClientError('Unsupported grant type: `grant_type` is invalid');
      }

      if ((responseTypeTemp.includes('code') && responseTypeTemp.length > 1) && !_.includes(client.grants, 'hybrid')) {
        throw new UnauthorizedClientError('Unsupported grant type: `grant_type` is invalid');
      }

      if (!client.redirectUris || 0 === client.redirectUris.length) {
        throw new InvalidClientError('Invalid client: missing client `redirectUri`');
      }

      if (redirectUri && !_.includes(client.redirectUris, redirectUri)) {
        throw new InvalidClientError('Invalid client: `redirect_uri` does not match client value');
      }
      return client;
    });
};

/**
 * Get scope from the request.
 */

AuthorizeHandler.prototype.getScope = function(request) {
  debug("======AuthorizeHandler: getScope======")
  var scope = request.body.scope || request.query.scope;


  if (!is.nqschar(scope)) {
    throw new InvalidScopeError('Invalid parameter: `scope`');
  }

  return scope;
};

/**
 * Get state from the request.
 */

AuthorizeHandler.prototype.getState = function(request) {
  debug("======AuthorizeHandler: getState======")
  var state = request.body.state || request.query.state;

  if (!this.allowEmptyState && !state) {
    throw new InvalidRequestError('Missing parameter: `state`');
  }

  if (state && !is.vschar(state)) {
    throw new InvalidRequestError('Invalid parameter: `state`');
  }

  return state;
};

/**
 * Get user by calling the authenticate middleware.
 */

AuthorizeHandler.prototype.getUser = function(request, response) {
    debug("======AuthorizeHandler: getUser======")
    if (request.body.user) {
      return request.body.user
    } else {

      if (!request.body.email) {
        throw new InvalidRequestError('Missing parameter: `email`');
      }

      if (!request.body.password) {
        throw new InvalidRequestError('Missing parameter: `password`');
      }

      if (!is.uchar(request.body.email)) {
        throw new InvalidRequestError('Invalid parameter: `username`');
      }

      if (!is.uchar(request.body.password)) {
        throw new InvalidRequestError('Invalid parameter: `password`');
      }

      return promisify(this.model.getUser, 2).call(this.model, request.body.email/*, request.body.password*/)
        .then(function(user) {
          if (!user) {
            throw new InvalidGrantError('Invalid grant: user credentials are invalid');
          }

          return user;
        });
    }

};

/**
 * Get redirect URI.
 */

AuthorizeHandler.prototype.getRedirectUri = function(request, client) {
  debug("======AuthorizeHandler: getrediretUri======")
  return request.body.redirect_uri || request.query.redirect_uri || client.redirectUris[0];
};

/**
 * Save authorization code.
 */

AuthorizeHandler.prototype.saveAuthorizationCode = function(authorizationCode, expiresAt, scope, client, redirectUri, user) {
  debug("======AuthorizeHandler: saveAuthzCode======")

  var code = {
    authorizationCode: authorizationCode,
    expiresAt: expiresAt,
    redirectUri: redirectUri,
    scope: scope
  };
  return promisify(this.model.saveAuthorizationCode, 3).call(this.model, code, client, user);
};


/**
 * Get access token lifetime.
 */

AuthorizeHandler.prototype.getAccessTokenLifetime = function(client) {
  debug("=====GetAccessTokenLifeTime=====")

  return client.accessTokenLifetime || this.accessTokenLifetime;
};

/**
 * Get id token lifetime.
 */

AuthorizeHandler.prototype.getIDTokenLifetime = function(client) {
  debug("=====GetIDTokenLifeTime=====")

  return client.idTokenLifetime || this.idTokenLifetime;
};

/**
 * Get token type.
 */

AuthorizeHandler.prototype.getTokenType = function(model) {
  debug("=====getTokenType=====")
  return new BearerTokenType(model.accessToken, model.accessTokenLifetime, model.refreshToken, model.scope, model.customAttributes);
};


/**
 * Build a successful response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildSuccessRedirectUri = function(redirectUri, responseType) {
  debug("======AuthorizeHandler: BuildSuccessRedirce======")
  return responseType.buildRedirectUri(redirectUri);
};

/**
 * Build an error response that redirects the user-agent to the client-provided url.
 */

AuthorizeHandler.prototype.buildErrorRedirectUri = function(redirectUri, error) {
  debug("======AuthorizeHandler: BuildErrorRedirce======")
  var uri = url.parse(redirectUri);

  uri.query = {
    error: error.name
  };

  if (error.message) {
    uri.query.error_description = error.message;
  }

  return uri;
};

/**
 * Update response with the redirect uri and the state parameter, if available.
 */

AuthorizeHandler.prototype.updateResponse = function(response, redirectUri, state, extended_query_parameters) {
  debug("======AuthorizeHandler: UpateResponse======")
  debug(extended_query_parameters)
  redirectUri.query = redirectUri.query || {};

  if (state) {
    redirectUri.query.state = state;
  }

  if (Object.keys(extended_query_parameters).length > 0) {
    redirectUri.query = _.assign(redirectUri.query, extended_query_parameters);
  }

  return url.format(redirectUri)
};

/**
 * Update response with the redirect uri and the state parameter, if available.
 */

AuthorizeHandler.prototype.getExtendedParameters = function(request) {
  debug("======AuthorizeHandler: getParameters======")

  var extra_parameters = JSON.parse(JSON.stringify(request.query))
  debug(extra_parameters)
  if (extra_parameters.client_id) {
    delete extra_parameters.client_id
  }
  if (extra_parameters.response_type) {
    if((extra_parameters.response_type == "code") || (extra_parameters.response_type == "id_token") || (extra_parameters.response_type == "id_token token") || (extra_parameters.response_type == "code id_token") || (extra_parameters.response_type == "code token") || (extra_parameters.response_type == "code id_token token")){
      delete extra_parameters.scope;
      delete extra_parameters.nonce;
    }
    delete extra_parameters.response_type
  }
  if (extra_parameters.code) {
    delete extra_parameters.code
  }
  if (extra_parameters.redirect_uri) {
    delete extra_parameters.redirect_uri
  }
  if (extra_parameters.state) {
    delete extra_parameters.state
  }

  return extra_parameters

};

/**
 * Export constructor.
 */

module.exports = AuthorizeHandler;
