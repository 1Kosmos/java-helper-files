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
import org.apache.http.HttpStatus;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class BIDSessions {
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

			// load from services
			Boolean keepAlive = true;
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

	public static BIDSession createNewSession(BIDTenantInfo tenantInfo, String authType, String scopes,
			Map<String, Object> metadataOrNull) {
		BIDSession ret = null;
		try {
			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String sessionsPublicKey = getPublicKey(sd.sessions);

			Map<String, Object> origin = new HashMap<>();
			origin.put("tag", communityInfo.tenant.tenanttag);
			origin.put("url", sd.adminconsole);
			origin.put("communityName", communityInfo.community.name);
			origin.put("communityId", communityInfo.community.id);
			origin.put("authPage", "blockid://authenticate");

			Map<String, Object> body = new HashMap<>();
			body.put("origin", origin);
			body.put("scopes", (scopes != null) ? scopes : "");
			body.put("authtype", (authType != null) ? authType : "none");

			if (metadataOrNull != null) {
				body.put("metadata", metadataOrNull);
			}

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, sessionsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Boolean keepAlive = true;
			Map<String, Object> response = WTM.execute("put", sd.sessions + "/session/new", headers,
					new Gson().toJson(body), keepAlive);

			String responseStr = (String) response.get("response");
			int statusCode = (Integer) response.get("status");

			ret = new Gson().fromJson(responseStr, BIDSession.class);
			ret.url = sd.sessions;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDSessionResponse pollSession(BIDTenantInfo tenantInfo, String sessionId, boolean fetchProfile,
			boolean fetchDevices, Map<String, Object> eventDataOrNull) {
		BIDSessionResponse ret = null;
		try {
			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String sessionsPublicKey = getPublicKey(sd.sessions);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, sessionsPublicKey);
			Boolean keepAlive = true;

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);
			headers.put("fetch_sessioninfo", Integer.toString(1));

			Map<String, Object> response = WTM.execute("get", sd.sessions + "/session/" + sessionId + "/response",
					headers, null, keepAlive);

			String responseStr = (String) response.get("response");
			int statusCode = (Integer) response.get("status");

			if (statusCode == HttpStatus.SC_NOT_FOUND) {
				ret = new BIDSessionResponse();
				ret.status = statusCode;
				ret.message = responseStr;
				return ret;
			}

			if (statusCode != HttpStatus.SC_OK) {
				// log event
				ret = new BIDSessionResponse();
				ret.status = statusCode;
				ret.message = responseStr;
				return ret;
			}

			ret = new Gson().fromJson(responseStr, BIDSessionResponse.class);
			ret.status = statusCode;

			if (ret.data != null) {
				System.out.println(" keySet.privateKey " + keySet.privateKey + " ret.publicKey " + ret.publicKey);
				String clientSharedKey = BIDECDSA.createSharedKey("bFt8HNj8hnOaU+R2TL2WcMv9L6gJJxWjcini8RyymMI=",
						ret.publicKey);
				String dec_data = BIDECDSA.decrypt(ret.data, clientSharedKey);
				System.out.println(" dec_data:: " + dec_data);
				ret.user_data = new Gson().fromJson(dec_data, Map.class);
			}

			if (ret != null && ret.data != null && ret.user_data.containsKey("did") && fetchProfile) {
				ret.account_data = BIDUsers.fetchUserByDID(tenantInfo, (String) ret.user_data.get("did"), fetchDevices);

			}

			Map<String, Object> metadata = ret.sessionInfo != null
					? (Map<String, Object>) ret.sessionInfo.get("metadata")
					: null;
			String purpose = (String) metadata.get("purpose");

			if (metadata != null && ((String) metadata.get("purpose")).toLowerCase().equals("authentication")) {
				String did = (String) ret.user_data.get("did");
				Map<String, Object> userData = (Map<String, Object>) ret.user_data.get("account");

				Map<String, Object> reason = new HashMap<>();

				Map<String, Object> account = new HashMap<>();
				account.put("username", userData.get("username"));
				account.put("uid", userData.get("uid"));
				account.put("authmoduleid", userData.get("authmoduleid"));
				account.put("source", userData.get("source"));

				Map<String, Object> userInfo = BIDUsers.fetchUserAccountsByDID(tenantInfo, did, true, true, account);

				Map<String, Object> requestId = WTM.makeRequestId();
				Map<String, Object> deviceData = (Map<String, Object>) userInfo.get("device");

				Map<String, Object> data = new HashMap<>();
				String eventName = "E_LOGIN_FAILED";
				data.put("type", "event");
				data.put("event_id", UUID.randomUUID().toString());
				data.put("event_ts", System.currentTimeMillis());
				data.put("version", "v1");
				data.put("session_id", sessionId);

				List<Object> users = (List<Object>) userInfo.get("users");

				if (!users.isEmpty() && users.size() == 1) {
					Map<String, Object> user = (Map<String, Object>) users.get(0);

					String status = (String) user.get("status");
					Boolean isDisabled = (Boolean) user.get("disabled");
					Boolean isLocked = (Boolean) user.get("isLocked");

					data.put("user_id", user.get("username"));
					data.put("user_status", status);
					data.put("user_email", user.get("email"));
					data.put("user_firstname", user.get("firstname"));
					data.put("user_lastname", user.get("lastname"));

					eventName = (status.equals("active") && !isDisabled && !isLocked) ? "E_LOGIN_SUCCEEDED"
							: "E_LOGIN_FAILED";

					data.put("event_name", "E_LOGIN_SUCCEEDED");
					data.put("login_state", "SUCCESS");

					if (isLocked) {
						data.put("login_state", "FAILED");
						data.put("event_name", "E_LOGIN_FAILED");
						reason.put("reason", "The user account has been locked");
					} else if (!status.equals("active")) {
						data.put("event_name", "E_LOGIN_FAILED");
						data.put("login_state", "FAILED");
						reason.put("reason", "The user account has not been active");
					} else if (isDisabled) {
						data.put("login_state", "FAILED");
						data.put("event_name", "E_LOGIN_FAILED");
						reason.put("reason", "The user account has been disabled");
					}

				} else {
					data.put("login_state", "FAILED");
					data.put("event_name", "E_LOGIN_FAILED");
					reason.put("reason", (users.size() != 1) ? "Multiple Users found" : "User not Found");

				}

				data.put("tenant_dns", tenantInfo.dns);
				data.put("tenant_tag", communityInfo.tenant.tenanttag);
				data.put("service_name", "Java Helper");
				data.put("auth_method", "qr");

				// Device Data
				data.put("device_id", deviceData.get("uid"));
				data.put("auth_device_os", deviceData.get("os"));
				data.put("auth_device_name", deviceData.get("deviceName"));
				data.put("auth_device_app_name", deviceData.get("authenticatorName"));
				data.put("auth_device_app_version", deviceData.get("authenticatorVersion"));
				data.put("auth_device_latitude", deviceData.get("locLat"));
				data.put("auth_device_longitude", deviceData.get("locLon"));

				if (eventDataOrNull != null) {
					data.putAll(eventDataOrNull);
				}

				if (!reason.isEmpty()) {
					data.put("eventData", reason);
				}

				// log event in reports service
				BIDReports.logEvent(tenantInfo, eventName, data, requestId);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;

	}
}
