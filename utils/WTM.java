/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk.utils;

import com.bidsdk.model.BIDSD;
import com.google.gson.Gson;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import java.net.URI;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.UUID;
import java.util.Optional;

public class WTM {

	public static Map<String, Object> makeRequestId(String uuid) {
		Map<String, Object> ret = new HashMap<>();
		ret.put("ts", Instant.now().getEpochSecond());
		ret.put("uuid", uuid != null ? uuid : UUID.randomUUID().toString());
		ret.put("appid", "java-helper");

		return ret;

	}

	public static Map<String, Object> makeRequestId() {
		Map<String, Object> ret = new HashMap<>();
		ret.put("ts", Instant.now().getEpochSecond());
		ret.put("uuid", UUID.randomUUID().toString());
		ret.put("appid", "java-helper");

		return ret;

	}

	public static Map<String, String> defaultHeaders() {
		return new HashMap<String, String>() {
			{
				put("Content-Type", "application/json");
				put("charset", "utf-8");
			}
		};
	}

	public static Map<String, Object> execute(String type, String url, Map<String, String> headers, String bodyStr,
			Boolean keepAlive) {
		Map<String, Object> ret = new HashMap<>();
		try {
			HttpClient httpclient = HttpClientBuilder.create().build();
			URIBuilder builder = new URIBuilder(url);
			URI uri = builder.build();
			HttpRequestBase request = null;
			if ("get".equalsIgnoreCase(type)) {
				request = new HttpGet(uri);
			} else if ("post".equalsIgnoreCase(type)) {
				request = new HttpPost(uri);
			} else if ("put".equalsIgnoreCase(type)) {
				request = new HttpPut(uri);
			} else if ("delete".equalsIgnoreCase(type)) {
				request = new HttpDelete(uri);
			}

			// add headers
			request.setHeader("Content-Type", "application/json");
			request.setHeader("charset", "utf-8");

			if (headers == null) {
				headers = new HashMap<>();
			}

			for (Map.Entry<String, String> entry : headers.entrySet()) {
				request.setHeader(entry.getKey(), entry.getValue());
			}

			if (keepAlive) {
				request.setHeader("Connection", "keep-alive");
			}

			// end - add headers

			if (bodyStr != null) {
				((HttpEntityEnclosingRequest) request).setEntity(new StringEntity(bodyStr));
			}

			HttpResponse response = httpclient.execute(request);
			HttpEntity entity = response.getEntity();

			String responseStr = (entity != null) ? EntityUtils.toString(entity).trim() : null;
			int statusCode = response.getStatusLine().getStatusCode();

			ret.put("status", statusCode);
			if (responseStr != null) {
				ret.put("response", responseStr);
			}
		} catch (Exception e) {
			ret.put("status", HttpStatus.SC_METHOD_FAILURE);
			ret.put("response", e.getMessage());
			ret.put("exception", e);
		}
		return ret;
	}
}
