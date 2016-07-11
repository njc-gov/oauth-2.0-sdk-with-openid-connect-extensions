package com.nimbusds.oauth2.sdk.auth.verifier;


import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;


/**
 * Invalid client exception. Selected static instances are provided to speed up
 * exception processing.
 */
public class InvalidClientException extends Exception {
	

	/**
	 * Bad {@code client_id}.
	 */
	public static final InvalidClientException BAD_ID = new InvalidClientException("Bad client ID");


	/**
	 * The client is not registered for the requested authentication
	 * method.
	 */
	public static final InvalidClientException NOT_REGISTERED_FOR_AUTH_METHOD = new InvalidClientException("The client is not registered for the requested authentication method");


	/**
	 * The client has no registered {@code client_secret}.
	 */
	public static final InvalidClientException NO_REGISTERED_SECRET = new InvalidClientException("The client has no registered secret");


	/**
	 * The client has no registered JWK set.
	 */
	public static final InvalidClientException NO_REGISTERED_JWK_SET = new InvalidClientException("The client has no registered JWK set");


	/**
	 * Expired {@code client_secret}.
	 */
	public static final InvalidClientException EXPIRED_SECRET = new InvalidClientException("Expired client secret");


	/**
	 * Bad {@code client_secret}.
	 */
	public static final InvalidClientException BAD_SECRET = new InvalidClientException("Bad client secret");


	/**
	 * Bad JWT claims (e.g. expired JWT).
	 */
	public static final InvalidClientException BAD_JWT_CLAIMS = new InvalidClientException("Bad / expired JWT claims");


	/**
	 * Bad JWT HMAC.
	 */
	public static final InvalidClientException BAD_JWT_HMAC = new InvalidClientException("Bad JWT HMAC");


	/**
	 * No matching public JWKs for JWT signature verification found.
	 */
	public static final InvalidClientException NO_MATCHING_JWK = new InvalidClientException("No matching JWKs found");


	/**
	 * Bad JWT signature.
	 */
	public static final InvalidClientException BAD_JWT_SIGNATURE = new InvalidClientException("Bad JWT signature");


	/**
	 * Creates a new invalid client exception.
	 *
	 * @param message The message.
	 */
	public InvalidClientException(final String message) {
		super(message);
	}


	/**
	 * Returns an OAuth 2.0 error object representation.
	 *
	 * @return {@link OAuth2Error#INVALID_CLIENT}.
	 */
	public ErrorObject toErrorObject() {
		return OAuth2Error.INVALID_CLIENT;
	}
}
