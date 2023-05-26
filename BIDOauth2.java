/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.*;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import com.kenai.jffi.Closure.Buffer;

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BIDOauth2 {

	public static Map<String, String> getQueryMap(String query) {
		String[] params = query.split("&");
		Map<String, String> map = new HashMap<String, String>();

		for (String param : params) {
			String name = param.split("=")[0];
			String value = param.split("=").length > 1 ? param.split("=")[1] : "";
			map.put(name, value);
		}
		return map;
	}

	public static BIDAuthorizationCodeResponse requestAuthorizationCode(BIDTenantInfo tenantInfo,
			String proofOfAuthenticationJwt, String clientId, String responseType, String scope, String redirectUri,
			String stateOrNull, String nonceOrNull) {
		BIDAuthorizationCodeResponse ret = new BIDAuthorizationCodeResponse();
		try {
			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String serviceUrl = sd.oauth2 + "/community/" + communityInfo.community.name + "/v1/authorize";

			HttpClient httpclient = HttpClientBuilder.create().disableRedirectHandling().build();
			URIBuilder builder = new URIBuilder(serviceUrl);
			URI uri = builder.build();
			HttpPost request = new HttpPost(uri);

			request.setHeader("Content-Type", "application/x-www-form-urlencoded");
			request.setHeader("charset", "utf-8");
			request.setHeader("Accept", "application/json");
			request.setHeader("Connection", "keep-alive");

			List<NameValuePair> body = new ArrayList<NameValuePair>();
			body.add(new BasicNameValuePair("client_id", clientId));
			body.add(new BasicNameValuePair("response_type", responseType));
			body.add(new BasicNameValuePair("scope", scope));
			body.add(new BasicNameValuePair("redirect_uri", redirectUri));
			body.add(new BasicNameValuePair("proof_of_authentication_jwt", proofOfAuthenticationJwt));

			if (stateOrNull != null) {
				body.add(new BasicNameValuePair("state", stateOrNull));
			}

			if (nonceOrNull != null) {
				body.add(new BasicNameValuePair("nonce", nonceOrNull));
			}

			request.setEntity(new UrlEncodedFormEntity(body));

			HttpResponse response = httpclient.execute(request);
			HttpEntity entity = response.getEntity();
			int statusCode = response.getStatusLine().getStatusCode();

			String responseStr = (entity != null) ? EntityUtils.toString(entity).trim() : null;

			if (statusCode != 200 && statusCode != 303) {
				ret = new Gson().fromJson(responseStr, BIDAuthorizationCodeResponse.class);
				return ret;
			}

			String location = response.getFirstHeader("Location") != null
					? response.getFirstHeader("Location").getValue()
					: null;

			String decodedUrl = URLDecoder.decode(location, "UTF-8");

			URL locationUrl = new URL(decodedUrl);

			Map<String, String> queryData = getQueryMap(locationUrl.getQuery());

			if (queryData.get("error") != null) {
				ret.statusCode = 400;
				ret.message = queryData.get("error_description");
				return ret;
			}

			ret.statusCode = statusCode;
			ret.url = location;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;
	}

	public static BIDTokenResponse requestToken(BIDTenantInfo tenantInfo, String clientId, String clientSecret,
			String grantType, String redirectUri, String codeOrNull, String refreshTokenOrNull) {
		BIDTokenResponse ret = null;
		try {
			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String serviceUrl = sd.oauth2 + "/community/" + communityInfo.community.name + "/v1/token";

			HttpClient httpclient = HttpClientBuilder.create().disableRedirectHandling().build();
			URIBuilder builder = new URIBuilder(serviceUrl);
			URI uri = builder.build();
			HttpPost request = new HttpPost(uri);

			String authString = clientId + ":" + clientSecret;
			byte[] authBytes = authString.getBytes();
			String authEncoded = Base64.getEncoder().encodeToString(authBytes);

			request.setHeader("Content-Type", "application/x-www-form-urlencoded");
			request.setHeader("charset", "utf-8");
			request.setHeader("Authorization", "Basic " + authEncoded);
			request.setHeader("Connection", "keep-alive");

			List<NameValuePair> body = new ArrayList<NameValuePair>();
			body.add(new BasicNameValuePair("grant_type", grantType));
			body.add(new BasicNameValuePair("redirect_uri", redirectUri));

			if (codeOrNull != null) {
				body.add(new BasicNameValuePair("code", codeOrNull));
			}

			if (refreshTokenOrNull != null) {
				body.add(new BasicNameValuePair("refresh_token", refreshTokenOrNull));
			}

			request.setEntity(new UrlEncodedFormEntity(body));

			HttpResponse response = httpclient.execute(request);
			HttpEntity entity = response.getEntity();
			int statusCode = response.getStatusLine().getStatusCode();

			String responseStr = (entity != null) ? EntityUtils.toString(entity).trim() : null;

			ret = new Gson().fromJson(responseStr, BIDTokenResponse.class);
			ret.status = statusCode;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;
	}
}
