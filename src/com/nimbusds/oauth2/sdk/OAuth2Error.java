package com.nimbusds.oauth2.sdk;


import java.net.URL;

import net.jcip.annotations.Immutable;


/**
 * OAuth 2.0 error. This class is immutable.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-28)
 */
@Immutable
public class OAuth2Error {

	
	// Base OAuth 2.0 authorisation errors
	
	/**
	 * The request is missing a required parameter, includes an invalid 
	 * parameter code, or is otherwise malformed.
	 */
	public static final OAuth2Error INVALID_REQUEST = 
		new OAuth2Error("invalid_request", "Invalid request");
	
	
	/**
	 * The client is not authorised to request an authorisation code using 
	 * this method.
	 */
	public static final OAuth2Error UNAUTHORIZED_CLIENT =
		new OAuth2Error("unauthorized_client", "Unauthorized client");
	
	
	/**
	 * The resource owner or authorisation server denied the request.
	 */
	public static final OAuth2Error ACCESS_DENIED =
		new OAuth2Error("access_denied", "Access denied by resource owner or authorization server");
	
	
	/**
	 * The authorisation server does not support obtaining an authorisation 
	 * code using this method.
	 */
	public static final OAuth2Error UNSUPPORTED_RESPONSE_TYPE =
		new OAuth2Error("unsupported_response_type", "Unsupported response type");
	
	
	/**
	 * The requested scope is invalid, unknown, or malformed.
	 */
	public static final OAuth2Error INVALID_SCOPE =
		new OAuth2Error("invalid_scope", "Invalid, unknown or malformed scope");
	
	
	/**
	 * The authorisation server encountered an unexpected condition which 
	 * prevented it from fulfilling the request.
	 */
	public static final OAuth2Error SERVER_ERROR =
		new OAuth2Error("server_error", "Unexpected server error");
	
	
	/**
	 * The authorisation server is currently unable to handle the request 
	 * due to a temporary overloading or maintenance of the server.
	 */
	public static final OAuth2Error TEMPORARILY_UNAVAILABLE =
		new OAuth2Error("temporarily_unavailable", "The authorization server is temporarily unavailable");
	
	
	// Token, Base OAuth 2.0 authorisation errors, section 5.2
	
	/**
	 * Client authentication failed (e.g. unknown client, no client 
	 * authentication included, or unsupported authentication method).
	 */
	public static final OAuth2Error INVALID_CLIENT =
		new OAuth2Error("invalid_client", "Client authentication failed");
	
	
	/**
	 * The provided authorisation grant (e.g. authorisation code, resource 
	 * owner credentials) or refresh token is invalid, expired, revoked, 
	 * does not match the redirection URI used in the authorization request,
	 * or was issued to another client.
	 */
	public static final OAuth2Error INVALID_GRANT =
		new OAuth2Error("invalid_grant", "Invalid grant");
	
	
	/**
	 * The authorisation grant type is not supported by the authorisation 
	 * server.
	 */
	public static final OAuth2Error UNSUPPORTED_GRANT_TYPE =
		new OAuth2Error("unsupported_grant_type", "Unsupported grant type");
	
	
	/**
	 * The error code, may not always be defined.
	 */
	private final String code;


	/**
	 * Optional error description.
	 */
	private final String description;


	/**
	 * Optional HTTP status code, 0 if not specified.
	 */
	private final int httpStatusCode;


	/**
	 * Optional URI of a web page that includes additional information 
	 * about the error.
	 */
	private final URL uri;


	/**
	 * Creates a new OAuth 2.0 error with the specified code.
	 *
	 * @param code The error code, {@code null} if not specified.
	 */
	public OAuth2Error(final String code) {
	
		this(code, null, 0, null);
	}
	
	
	/**
	 * Creates a new OAuth 2.0 error with the specified code and 
	 * description.
	 *
	 * @param code        The error code, {@code null} if not specified.
	 * @param description The error description, {@code null} if not
	 *                    specified.
	 */
	public OAuth2Error(final String code, final String description) {
	
		this(code, description, 0, null);
	}


	/**
	 * Creates a new OAuth 2.0 error with the specified code, description
	 * and HTTP status code.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 */
	public OAuth2Error(final String code, final String description, 
		           final int httpStatusCode) {
	
		this(code, description, httpStatusCode, null);
	}


	/**
	 * Creates a new OAuth 2.0 error with the specified code, description,
	 * HTTP status code and and page URI.
	 *
	 * @param code           The error code, {@code null} if not specified.
	 * @param description    The error description, {@code null} if not
	 *                       specified.
	 * @param httpStatusCode The HTTP status code, zero if not specified.
	 * @param uri            The error page URI, {@code null} if not
	 *                       specified.
	 */
	public OAuth2Error(final String code, final String description, 
		           final int httpStatusCode, final URL uri) {
	
		this.code = code;
		this.description = description;
		this.httpStatusCode = httpStatusCode;
		this.uri = uri;
	}


	/**
	 * Gets the error code.
	 *
	 * @return The error code, {@code null} if not specified.
	 */
	public String getCode() {

		return code;
	}
	
	
	/**
	 * Gets the error description.
	 *
	 * @return The error description, {@code null} if not specified.
	 */
	public String getDescription() {
	
		return description;
	}


	/**
	 * Sets the error description.
	 *
	 * @param description The error description, {@code null} if not 
	 *                    specified.
	 *
	 * @return A copy of this error with the specified description.
	 */
	public OAuth2Error setDescription(final String description) {

		return new OAuth2Error(getCode(), description, getHTTPStatusCode(), getURI());
	}


	/**
	 * Appends the specified text to the error description.
	 *
	 * @param text The text to append to the error description, 
	 *             {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified appended 
	 *         description.
	 */
	public OAuth2Error appendDescription(final String text) {

		String newDescription;

		if (getDescription() != null)
			newDescription = getDescription() + text;
		else
			newDescription = text;

		return new OAuth2Error(getCode(), newDescription, getHTTPStatusCode(), getURI());
	}


	/**
	 * Gets the HTTP status code.
	 *
	 * @return The HTTP status code, zero if not specified.
	 */
	public int getHTTPStatusCode() {

		return httpStatusCode;
	}


	/**
	 * Sets the HTTP status code.
	 *
	 * @param httpStatusCode  The HTTP status code, zero if not specified.
	 *
	 * @return A copy of this error with the specified HTTP status code.
	 */
	public OAuth2Error setHTTPStatusCode(final int httpStatusCode) {

		return new OAuth2Error(getCode(), getDescription(), httpStatusCode, getURI());
	}


	/**
	 * Gets the error page URI.
	 *
	 * @return The error page URI, {@code null} if not specified.
	 */
	public URL getURI() {

		return uri;
	}


	/**
	 * Sets the error page URI.
	 *
	 * @param uri The error page URI, {@code null} if not specified.
	 *
	 * @return A copy of this error with the specified page URI.
	 */
	public OAuth2Error setURI(final URL uri) {

		return new OAuth2Error(getCode(), getDescription(), getHTTPStatusCode(), uri);
	}


	/**
	 * @see #getCode
	 */
	@Override
	public String toString() {
	
		if (code != null)
			return code;
		else
			return "null";
	}


	@Override
	public int hashCode() {
	
		if (code != null)
			return code.hashCode();
		else
			return "null".hashCode();
	}


	@Override
	public boolean equals(final Object object) {
	
		return object != null && 
		       object instanceof OAuth2Error && 
		       this.toString().equals(object.toString());
	}
}