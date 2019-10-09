/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.openid.connect.sdk;


import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import net.minidev.json.JSONObject;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Test;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.client.ClientRegistrationResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.http.X509CertificateGenerator;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientInformation;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientRegistrationResponseParser;


/**
 * Client registration and conformance test configuration generation for FAPI
 * Read/Write OPs.
 *
 * <p>See https://openid.net/certification/fapi_op_testing/
 */
public class FAPICertTest {
	
	
	static final Issuer ISSUER = new Issuer("https://demo.c2id.com/c2id");
	
	
	static RSAKey generateRSAJWKWithSelfSignedCertificate()
		throws Exception {
		
		return new RSAKeyGenerator(2048)
			.keyID("fapi-" + new Random().nextInt())
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.PS256)
			.generate();
	}
	
	
	static X509Certificate createSelfSignedCertificate(final RSAKey rsaJWK)
		throws Exception {
		
		return X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("client"),
			rsaJWK.toRSAPublicKey(),
			rsaJWK.toRSAPrivateKey());
	}
	
	
	static RSAKey appendCertificate(final RSAKey rsaJWK, final X509Certificate cert)
		throws CertificateEncodingException {
		
		return new RSAKey.Builder(rsaJWK)
			.x509CertChain(Collections.singletonList(Base64.encode(cert.getEncoded())))
			.build();
	}
	
	
	static URI createRedirectURI(final String alias) {
		
		return URI.create("https://www.certification.openid.net/test/a/" + alias + "/callback");
	}
	
	
	static URI createRedirectURIAlt(final String alias) {
		
		return URI.create("https://www.certification.openid.net/test/a/" + alias + "/callback?dummy1=lorem&dummy2=ipsum");
	}
	
	
	static OIDCClientMetadata createClientMetadata(final String opAlias, final RSAKey clientRSAJWK) {
		
		OIDCClientMetadata clientMetadata = new OIDCClientMetadata();
		clientMetadata.setGrantTypes(new HashSet<>(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN)));
		clientMetadata.setResponseTypes(new HashSet<>(Arrays.asList(new ResponseType("code"), new ResponseType("code", "id_token"))));
		clientMetadata.setRedirectionURIs(new HashSet<>(
			Arrays.asList(createRedirectURI(opAlias), createRedirectURIAlt(opAlias))
		));
		clientMetadata.setJWKSet(new JWKSet(clientRSAJWK));
		clientMetadata.setTokenEndpointAuthMethod(ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH);
		clientMetadata.setTLSClientCertificateBoundAccessTokens(true);
		clientMetadata.applyDefaults();
		
		return clientMetadata;
	}
	
	
	static String toPEMEncodedString(final RSAKey rsaJWK) throws JOSEException {
		
		String out = "-----BEGIN PRIVATE KEY-----\n";
		out += Base64.encode(rsaJWK.toPrivateKey().getEncoded()).toString();
		out += "\n-----END PRIVATE KEY-----\n";
		return out;
	}
	
	
	@Test
	public void registerTestClientsAndPrintConfig()
		throws Exception {
		
		String opAlias = "c2id";
		
		URL configURL = OIDCProviderMetadata.resolveURL(ISSUER);
		
		OIDCProviderMetadata opMetadata = OIDCProviderMetadata.resolve(ISSUER);
		
		// Client 1
		RSAKey client1RSAJWK = generateRSAJWKWithSelfSignedCertificate();
		X509Certificate client1Cert = createSelfSignedCertificate(client1RSAJWK);
		client1RSAJWK = appendCertificate(client1RSAJWK, client1Cert);
		OIDCClientRegistrationRequest regRequest = new OIDCClientRegistrationRequest(
			opMetadata.getRegistrationEndpointURI(),
			createClientMetadata(opAlias, client1RSAJWK),
			null);
		HTTPResponse httpResponse = regRequest.toHTTPRequest().send();
		ClientRegistrationResponse clientRegResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);
		if (! clientRegResponse.indicatesSuccess()) {
			fail(clientRegResponse.toErrorResponse().getErrorObject().toJSONObject().toJSONString());
		}
		OIDCClientInformation clientInfo1 = (OIDCClientInformation) clientRegResponse.toSuccessResponse().getClientInformation();
		
		// Client 2
		RSAKey client2RSAJWK = generateRSAJWKWithSelfSignedCertificate();
		X509Certificate client2Cert = createSelfSignedCertificate(client2RSAJWK);
		client2RSAJWK = appendCertificate(client2RSAJWK, client2Cert);
		regRequest = new OIDCClientRegistrationRequest(
			opMetadata.getRegistrationEndpointURI(),
			createClientMetadata(opAlias, client2RSAJWK),
			null);
		httpResponse = regRequest.toHTTPRequest().send();
		clientRegResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);
		OIDCClientInformation clientInfo2 = (OIDCClientInformation) clientRegResponse.toSuccessResponse().getClientInformation();
		
		
		// See https://gitlab.com/openid/conformance-suite/wikis/Authlete-Example-Configuration
		JSONObject config = new JSONObject();
		config.put("alias", opAlias);
		config.put("description", "Connect2id server FAPI-RW with private RSA key");
		
		JSONObject serverConfig = new JSONObject();
		serverConfig.put("discoveryUrl", configURL.toString().replace("\\/", "/"));
		config.put("server", serverConfig);
		
		JSONObject clientConfig = new JSONObject();
		clientConfig.put("client_id", clientInfo1.getID().getValue());
		clientConfig.put("scope", "openid");
		clientConfig.put("jwks", new JWKSet(client1RSAJWK).toJSONObject(false));
		config.put("client", clientConfig);
		
		JSONObject resourceConfig = new JSONObject();
		resourceConfig.put("resourceUrl", opMetadata.getUserInfoEndpointURI().toString());
		resourceConfig.put("institution_id", "xxx");
		config.put("resource", resourceConfig);
		
		JSONObject client2Config = new JSONObject();
		client2Config.put("client_id", clientInfo2.getID().getValue());
		client2Config.put("scope", "openid");
		client2Config.put("jwks", new JWKSet(client2RSAJWK).toJSONObject(false));
		config.put("client2", client2Config);
		
		JSONObject mtlsConfig = new JSONObject();
		mtlsConfig.put("cert", X509CertUtils.toPEMString(client1Cert));
		mtlsConfig.put("key", toPEMEncodedString(client1RSAJWK));
		config.put("mtls", mtlsConfig);
		
		JSONObject mtls2Config = new JSONObject();
		mtls2Config.put("cert", X509CertUtils.toPEMString(client2Cert));
		mtls2Config.put("key", toPEMEncodedString(client2RSAJWK));
		config.put("mtls2", mtls2Config);
		
		// Cert suite JSON parser doesn't accept escaped '/'
		System.out.println(config.toJSONString().replace("\\/", "/"));
		
		String pemCert = "-----BEGIN CERTIFICATE-----\nMIICozCCAYugAwIBAgIJAMGhzYtwkpbsMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBmNsaWVudDAeFw0xOTA3MjQwOTA2MzVaFw0yMDA3MjMwOTA2MzZaMBExDzANBgNVBAMMBmNsaWVudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ4baw1W6WJl1BdsoTPWN//UvcsqDtN1SwoiYhLmP6uBlRPLxU/F3bkSMQxB6J4yaaMW86tThUlEiRjm+VRvGK6QmmYyyb9Cyv3YSbNNXNz00Zb3t93cBENqqypzOo1HzpMbY4/6GnJ4cETbuqbVgY0TungTCJjRgqOpho30p6BfevuLLV2SNYyqi499bYYy1kFTyt0iHRDzgkBbrYt6CtASsor+0eeSLi8NxPXQ+nx8LtvOEepyy7M3ejhqqpIHXXv14PQyhB+N4SArdHm7Od7+S8PagUamQ4MLTIcjv4Eo0Kgs/FciK3Nx2gXO6o1R/NN9hRJ1pFqkzYzlXl0mnyUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAGW8rpIKNQuKdUMiJLoiLce0G4lFq0DoQJ7NXKIVclig3kx8kF6X5IcohhLApAKcarghG6GjDXT7nGTEWwYy2QG+ML/z2dRT6znCS0zSiodM1tdSo2WsveZCYGYWbknZpMR/tfJhD29mSu61O8aiyVIXh5FL5givpsu+w1oMqZ0ADsCQN+3GKit+ybzgyAatCKldwCE4qp79I5T4Dxi5EADDjs8PUnwYZm8YdR7CP3N1Ubq99/PfWNxt8XlKunK1f+BjBKENi+rIrvYNBHxWK9Fn7KLR7slWf0HaXHU4QbdEWkBsJ8HbMyg+/HN/eNX+lrSNJ1i1GRKWrDTTlS1pcTQ==\n-----END CERTIFICATE-----";
		assertEquals("", X509CertUtils.parse(pemCert).getIssuerDN());
		
	}
}
