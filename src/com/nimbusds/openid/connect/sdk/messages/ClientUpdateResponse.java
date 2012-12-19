package com.nimbusds.openid.connect.sdk.messages;


import net.jcip.annotations.Immutable;

import net.minidev.json.JSONObject;

import com.nimbusds.openid.connect.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.SerializeException;

import com.nimbusds.openid.connect.sdk.claims.ClientID;

import com.nimbusds.openid.connect.sdk.http.CommonContentTypes;
import com.nimbusds.openid.connect.sdk.http.HTTPResponse;


/**
 * Client update responses. This class is immutable.
 *
 * <p>Example HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 * Cache-Control: no-store
 * 
 * {
 *  "client_id":"s6BhdRkqt3"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 2.2.2.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-12-19)
 */
@Immutable
public final class ClientUpdateResponse extends ClientRegistrationResponse {


	/**
	 * Creates a new client update response.
	 *
	 * @param clientID The client ID. Must not be {@code null}.
	 */
	public ClientUpdateResponse(final ClientID clientID) {

		super(clientID);
	}


	@Override
	public HTTPResponse toHTTPResponse()
		throws SerializeException {
	
		HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
		
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setCacheControl("no-store");

		JSONObject json = new JSONObject();

		json.put("client_id", getClientID().getClaimValue());
		
		httpResponse.setContent(json.toString());
	
		return httpResponse;
	}
}