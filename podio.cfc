/*
  Copyright (c) 2018, Matthew Clemente, John Berquist
  v0.0.1

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
component output="false" displayname="podio.cfc"  {

  public any function init( required string clientId, required string clientSecret, string baseUrl = "https://api.podio.com",  numeric httpTimeout = 60, boolean includeRaw = true, any sessionManager = '' ) {

    structAppend( variables, arguments );

    //if the session manager is a string, use it to make a new object
    if ( isSimpleValue( variables.sessionManager ) && variables.sessionManager.len() )
      variables[ 'sessionManager' ] = new '#arguments.sessionManager#'();

    //unset sessionManager it doesn't have required methods
    if ( isObject( variables.sessionManager ) && ( !structKeyExists( variables.sessionManager, 'get' ) || !structKeyExists( variables.sessionManager, 'set' ) ) )
      variables[ 'sessionManager' ] = '';

    //credentials struct is used if there is no session manager
    variables[ 'credentials' ] = {};

    variables[ 'oauth' ] = returnTokenFromMemory();

    return this;
  }

  /**
  * @hint
  */
  public struct function returnTokenFromMemory( struct authType = {} ) {
    var auth = {};
    //if we have a session manager, use it
    if ( hasSessionManager() )
      auth = variables.sessionManager.get( authType = authType);
    else
      auth = getCredentials( authType = authType );

    //if not set by session manager
    if ( auth.isEmpty() ) {
      auth = {
        'access_token' = '',
        'refresh_token' = '',
        'expires_in' = '',
        'type' = {
          'type' = '',
          'id' = ''
        }
      };
    }

    return auth;
  }

  public struct function authenticateWithApp( required numeric appID, required string appToken ) {
    var credentials = {
      'app_id' : appId,
      'app_token' : appToken
    };
    return authenticate( 'app', credentials );
  }

  public struct function authenticateWithCredentials( required string username, required string password ) {
    var credentials = {
      'username' : username,
      'password' : password
    };
    return authenticate( 'password', credentials );
  }

  public struct function authenticateWithAuthorizationCode( required string authorizationCode, required string redirectUri ) {
    var credentials = {
      'code' : authorizationCode,
      'redirect_uri' : redirectUri
    };
    return authenticate( 'authorization_code', credentials );
  }

  public struct function refreshAccessToken() {
    var credentials = {
      'refresh_token' : variables.oauth.refresh_token
    };
    return authenticate( 'refresh_token', credentials );
  }

  /**
  * @hint technically this doesn't need to return anything, or could simply return a boolean. However, to make debugging a little clearer, it's returning the oauth object that gets created.
  */
  public struct function authenticate( required string grantType, required struct credentials ) {
    var data = { 'grant_type' : grantType };
    data.append( credentials );

    var authType = {
      'type' : grantType,
      'identifier' : ''
    };

    if ( grantType == 'password' )
      authType[ 'identifier' ] = credentials.username;
    else if ( grantType == 'app' )
      authType[ 'identifier' ] = credentials.app_id;

    data[ 'client_id' ] = variables.clientId;
    data[ 'client_secret' ] = variables.clientSecret;

    var headers = {
      'Content-Type' = 'application/x-www-form-urlencoded'
    };

    var accessRequest = apiCall( 'POST', '/oauth/token', data, {}, headers );

    if ( !accessRequest.keyExists( 'statusCode' ) || accessRequest.statusCode != 200 )
      throw( 'An error occurred while requesting a Podio access token.' );
    else
      variables[ 'oauth' ] = accessRequest.data;

    //we're gonna set a stamp for when the token expires
    variables[ 'oauth' ][ 'expiration' ] = now().add( 's', accessRequest.data.expires_in );

    // Don't touch auth_type if we are refreshing automatically as it'll be reset to null
    if ( grantType != 'refresh_token' )
      variables[ 'authType' ] = authType;

    if ( hasSessionManager() )
      variables.sessionManager.set( oauth = variables.oauth, authType = authType );
    else
      setCredentials( oauth = variables.oauth, authType = authType );

    return variables.oauth;
  }

  /**
  * @hint makes sure that the token is present and has at least one minute remaining before expiration
  */
  public boolean function isAuthenticated() {
    return variables.keyExists( 'oauth' ) && variables.oauth.access_token.len() && variables.oauth.expiration.diff( 'n', now() ) >= 1;
  }

  private boolean function hasSessionManager() {
    return isObject( variables.sessionManager );
  }

  /******************************************************
  * Methods for internally handling credentials, if there is no external session manager
  ******************************************************/

  /**
  * @hint If there is no session manager, we will attempt to retrieve the credentials from within the object itself
  */
  private struct function getCredentials( struct authType = {} ) {
    if ( authType.isEmpty() )
      return {};

    var cacheKey = returnCacheKey( authType );

    return variables.credentials.keyExists( cacheKey )
      ? variables.credentials[ cacheKey ]
      : {};
  }

  /**
  * @hint If there is no session manager, we will store the credentials within the object itself
  */
  private void function setCredentials( required struct oauth, required struct authType ) {
    var cacheKey = returnCacheKey( authType );
    variables.credentials[ '#cacheKey#' ] = oauth;
  }

  /**
  * @hint helper for internal credential storing methods
  */
  private string function returnCacheKey( required struct authType ) {
    return 'internalCache_' & authType.type & '_' & authType.identifier;
  }

  // API CALL RELATED PRIVATE FUNCTIONS
  private struct function apiCall(
    required string httpMethod,
    required string path,
    struct queryParams = { },
    any body = '',
    struct headers = { } )  {

    var fullApiPath = variables.baseUrl & path;
    var requestHeaders = getBaseHttpHeaders();
    requestHeaders.append( headers, true );

    var requestStart = getTickCount();
    var apiResponse = makeHttpRequest( httpMethod = httpMethod, path = fullApiPath, queryParams = queryParams, headers = requestHeaders, body = body );

    var result = {
      'responseTime' = getTickCount() - requestStart,
      'statusCode' = listFirst( apiResponse.statuscode, " " ),
      'statusText' = listRest( apiResponse.statuscode, " " )
    };

    var deserializedFileContent = {};

    if ( isJson( apiResponse.fileContent ) )
      deserializedFileContent = deserializeJSON( apiResponse.fileContent );

    //needs to be cusomtized by API integration for how errors are returned
    if ( result.statusCode >= 400 ) {
      if ( isStruct( deserializedFileContent ) )
        result.append( deserializedFileContent );
    }

    //stored in data, because some responses are arrays and others are structs
    result[ 'data' ] = deserializedFileContent;

    if ( variables.includeRaw ) {
      result[ 'raw' ] = {
        'method' : ucase( httpMethod ),
        'path' : fullApiPath,
        'params' : serializeJSON( queryParams ),
        'response' : apiResponse.fileContent,
        'responseHeaders' : apiResponse.responseheader
      };
    }

    return result;
  }

  private struct function getBaseHttpHeaders() {
    return {
      'Content-Type' : 'application/json',
      'User-Agent' : 'podio.cfc'
    };
  }

  private any function makeHttpRequest(
    required string httpMethod,
    required string path,
    struct queryParams = { },
    struct headers = { },
    any body = ''
  ) {
    var result = '';

    var fullPath = path & ( !queryParams.isEmpty()
      ? ( '?' & parseQueryParams( queryParams, false ) )
      : '' );

    var requestHeaders = parseHeaders( headers );
    var requestBody = parseBody( body );

    cfhttp( url = fullPath, method = httpMethod, result = 'result' ) {

      for ( var header in requestHeaders ) {
        cfhttpparam( type = "header", name = header.name, value = header.value );
      }

      if ( arrayFindNoCase( [ 'POST','PUT','PATCH','DELETE' ], httpMethod ) && isJSON( requestBody ) )
        cfhttpparam( type = "body", value = requestBody );

    }
    return result;
  }

  /**
  * @hint convert the headers from a struct to an array
  */
  private array function parseHeaders( required struct headers ) {
    var sortedKeyArray = headers.keyArray();
    sortedKeyArray.sort( 'textnocase' );
    var processedHeaders = sortedKeyArray.map(
      function( key ) {
        return { name: key, value: trim( headers[ key ] ) };
      }
    );
    return processedHeaders;
  }

  /**
  * @hint converts the queryparam struct to a string, with optional encoding and the possibility for empty values being pass through as well
  */
  private string function parseQueryParams( required struct queryParams, boolean encodeQueryParams = true, boolean includeEmptyValues = true ) {
    var sortedKeyArray = queryParams.keyArray();
    sortedKeyArray.sort( 'text' );

    var queryString = sortedKeyArray.reduce(
      function( queryString, queryParamKey ) {
        var encodedKey = encodeQueryParams
          ? encodeUrl( queryParamKey )
          : queryParamKey;
        if ( !isArray( queryParams[ queryParamKey ] ) ) {
          var encodedValue = encodeQueryParams && len( queryParams[ queryParamKey ] )
            ? encodeUrl( queryParams[ queryParamKey ] )
            : queryParams[ queryParamKey ];
        } else {
          var encodedValue = encodeQueryParams && ArrayLen( queryParams[ queryParamKey ] )
            ?  encodeUrl( serializeJSON( queryParams[ queryParamKey ] ) )
            : queryParams[ queryParamKey ].toList();
          }
        return queryString.listAppend( encodedKey & ( includeEmptyValues || len( encodedValue ) ? ( '=' & encodedValue ) : '' ), '&' );
      }, ''
    );

    return queryString.len() ? queryString : '';
  }

  private string function parseBody( required any body ) {
    if ( isStruct( body ) || isArray( body ) )
      return serializeJson( body );
    else if ( isJson( body ) )
      return body;
    else
      return '';
  }

  private string function encodeUrl( required string str, boolean encodeSlash = true ) {
    var result = replacelist( urlEncodedFormat( str, 'utf-8' ), '%2D,%2E,%5F,%7E', '-,.,_,~' );
    if ( !encodeSlash ) result = replace( result, '%2F', '/', 'all' );

    return result;
  }

}