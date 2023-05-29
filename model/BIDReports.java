/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.*;
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

public class BIDReports {

	private static String getPublicKey(String baseUrl) {
		String ret = null;
		try {
			String url = baseUrl + "/publickeys";

			String cache_key = url;
			String cache_str = InMemCache.getInstance().get(cache_key);
			if (cache_str != null) {
				Map<String, String> map = new Gson().fromJson(cache_str, Map.class);
				ret = map.get("publicKey");
				return ret;
			}

			Boolean keepAlive = true;

			// load from services
			Map<String, Object> response = WTM.execute("get", url, WTM.defaultHeaders(), null, keepAlive);
			String responseStr = (String) response.get("response");

			int statusCode = (Integer) response.get("status");

			if (statusCode == 200) {
				Map<String, String> map = new Gson().fromJson(responseStr, Map.class);

				ret = map.get("publicKey");
				InMemCache.getInstance().set(cache_key, responseStr);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;
	}

	public static String logEvent(BIDTenantInfo tenantInfo, String eventName, Map<String, Object> data,
			Map<String, Object> requestId) {
		String ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String reportPublicKey = getPublicKey(sd.reports);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, reportPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid",
					BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId((String) requestId.get("uuid"))), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Boolean keepAlive = true;

			String enc_data = BIDECDSA.encrypt(new Gson().toJson(data), sharedKey);
			Map<String, Object> body = new HashMap<>();
			body.put("data", enc_data);

			Map<String, Object> response = WTM.execute(
					"put", sd.reports + "/tenant/" + communityInfo.tenant.id + "/community/"
							+ communityInfo.community.id + "/event/" + eventName,
					headers, new Gson().toJson(body), keepAlive);

			String responseStr = (String) response.get("response");
			int statusCode = (Integer) response.get("status");

			ret = responseStr;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;
	}
}
