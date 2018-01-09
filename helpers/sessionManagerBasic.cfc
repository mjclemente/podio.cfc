/*
  This is an extremely basic example of a session manager. It is not meant to be used in production. It should serve as a jumping off point for creating your own session manager.
*/
component accessors="true" {

  public any function init() {
    try {
      //var test = structKeyList( session );
      session[ 'podioSessionManagement' ] = true;
    } catch( any e ) {
      throw( 'Session management needs to be enabled in order to use the session manager.' );
    }
    return this;
  }

  /**
  * @hint Get oauth object from session, if present.
  * @authType is ignored for basic session management
  */
  public struct function get( struct authType = {} ) {

    var cacheKey = returnCacheKey( authType );

    return session.keyExists( cacheKey )
      ? session[ cacheKey ]
      : {};
  }

  /**
  * @hint Store the oauth object in the session
  * @authType is ignored for basic session management
  */
  public void function set( required struct oauth, required struct authType ) {
    var cacheKey = returnCacheKey( authType );
    session[ '#cacheKey#' ] = oauth;
  }

  private string function returnCacheKey( required struct authType ) {
    return 'podioSessionCache';
  }

}