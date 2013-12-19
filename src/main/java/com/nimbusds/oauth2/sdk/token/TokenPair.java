package com.nimbusds.oauth2.sdk.token;


import net.minidev.json.JSONObject;

import net.jcip.annotations.Immutable;


/**
 * Access and refresh token pair.
 */
@Immutable
public final class TokenPair {


	/**
	 * Access token.
	 */
	private final AccessToken accessToken;


	/**
	 * Refresh token, {@code null} if not specified.
	 */
	private final RefreshToken refreshToken;


	/**
	 * Creates a new access and refresh token pair.
	 *
	 * @param accessToken  The access token. Must not be {@code null}.
	 * @param refreshToken The refresh token. If none {@code null}.
	 */
	public TokenPair(final AccessToken accessToken, final RefreshToken refreshToken) {

		if (accessToken == null)
			throw new IllegalArgumentException("The access token must not be null");

		this.accessToken = accessToken;

		this.refreshToken = refreshToken;
	}
	

	/**
	 * Returns the access token.
	 *
	 * @return The access token.
	 */
	public AccessToken getAccessToken() {

		return accessToken;
	}


	/**
	 * Returns the refresh token.
	 *
	 * @return The refresh token, {@code null} if none.
	 */
	public RefreshToken getRefreshToken() {

		return refreshToken;
	}


	/**
	 * Returns the JSON object representation of this token pair.
	 *
	 * <p>Example JSON object:
	 *
	 * <pre>
	 * {
	 *   "access_token"  : "dZdt8BlltORMTz5U",
	 *   "refresh_token" : "E87zjAoeNXaSoF1U"
	 * }
	 * </pre>
	 *
	 * @return The JSON object representation.
	 */
	public JSONObject toJSONObject() {

		JSONObject o = accessToken.toJSONObject();

		if (refreshToken != null)
			o.putAll(refreshToken.toJSONObject());

		return o;
	}


	@Override
	public String toString() {

		return "TokenPair [accessToken=" + accessToken + " refreshToken=" + refreshToken + "]";
	}
}
