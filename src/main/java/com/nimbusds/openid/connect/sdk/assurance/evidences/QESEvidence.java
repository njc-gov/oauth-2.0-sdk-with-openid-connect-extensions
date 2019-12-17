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

package com.nimbusds.openid.connect.sdk.assurance.evidences;


import net.jcip.annotations.Immutable;
import net.minidev.json.JSONAware;
import net.minidev.json.JSONObject;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.oauth2.sdk.util.date.DateWithTimeZoneOffset;


/**
 * Qualified electronic signature (QES) used as identity evidence.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect for Identity Assurance 1.0, section 4.1.1.
 * </ul>
 */
@Immutable
public final class QESEvidence extends IdentityEvidence implements JSONAware {
	
	
	/**
	 * The QES issuer.
	 */
	private final Issuer issuer;
	
	
	/**
	 * The QES serial number.
	 */
	private final String serialNumber;
	
	
	/**
	 * The QES creation time.
	 */
	private final DateWithTimeZoneOffset createdAt;
	
	
	/**
	 * Creates a new QES used as identity evidence.
	 *
	 * @param issuer       The QES issuer. Must not be {@code null}.
	 * @param serialNumber The QES serial number. Must not be
	 *                     {@code null}.
	 * @param createdAt    The QES creation time. Must not be {@code null}.
	 */
	public QESEvidence(final Issuer issuer, final String serialNumber, final DateWithTimeZoneOffset createdAt) {
		
		super(IdentityEvidenceType.QES);
		
		if (issuer == null) {
			throw new IllegalArgumentException("The QES issuer must not be null");
		}
		this.issuer = issuer;
		
		if (serialNumber == null) {
			throw new IllegalArgumentException("The QES serial number must not be null");
		}
		this.serialNumber = serialNumber;
		
		if (createdAt == null) {
			throw new IllegalArgumentException("The QES creation time must not be null");
		}
		this.createdAt = createdAt;
	}
	
	
	/**
	 * Returns the QES issuer.
	 * @return The QES issuer.
	 */
	public Issuer getQESIssuer() {
		return issuer;
	}
	
	
	/**
	 * Returns the QES serial number.
	 *
	 * @return The QES serial number string.
	 */
	public String getQESSerialNumberString() {
		return serialNumber;
	}
	
	
	/**
	 * Returns The QES creation time.
	 *
	 * @return The QES creation time.
	 */
	public DateWithTimeZoneOffset getQESCreationTime() {
		return createdAt;
	}
	
	
	@Override
	public JSONObject toJSONObject() {
		
		JSONObject o = super.toJSONObject();
		o.put("issuer", getQESIssuer().getValue());
		o.put("serial_number", getQESSerialNumberString());
		o.put("created_at", getQESCreationTime().toISO8601String());
		return o;
	}
	
	
	/**
	 * Parses a new QES evidence from the specified JSON object.
	 *
	 * @param jsonObject The JSON object. Must not be {@code null}.
	 *
	 * @return The QES evidence.
	 *
	 * @throws ParseException If parsing failed.
	 */
	public static QESEvidence parse(final JSONObject jsonObject)
		throws ParseException {
		
		ensureType(IdentityEvidenceType.QES, jsonObject);
		Issuer issuer = new Issuer(JSONObjectUtils.getString(jsonObject, "issuer"));
		String serialNumber = JSONObjectUtils.getString(jsonObject, "serial_number");
		DateWithTimeZoneOffset createdAt = DateWithTimeZoneOffset.parseISO8601String(JSONObjectUtils.getString(jsonObject, "created_at"));
		return new QESEvidence(issuer, serialNumber, createdAt);
	}
}