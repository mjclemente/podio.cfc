/*
  This is an example of how a session manager might handle multiple authentications. It is not meant to be used in production. It should serve as a jumping off point for creating your own session manager, using something more permanent for the tokens, like Redis or SQL Server
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
  * @hint Get oauth object from session, if present. We use authType as the basis for the cache key.
  */
  public struct function get( struct authType = {} ) {

    if ( authType.isEmpty() )
      return {};

    var cacheKey = returnCacheKey( authType );

    return session.keyExists( cacheKey )
      ? session[ cacheKey ]
      : {};
  }

  public void function set( required struct oauth, required struct authType ) {
    var cacheKey = returnCacheKey( authType );
    session[ '#cacheKey#' ] = oauth;
  }

  private string function returnCacheKey( required struct authType ) {
    return 'podioCache_' & authType.type & '_' & authType.identifier;
  }

}