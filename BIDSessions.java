/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.http.HttpStatus;

import com.bidsdk.model.BIDCommunityInfo;
import com.bidsdk.model.BIDKeyPair;
import com.bidsdk.model.BIDSD;
import com.bidsdk.model.BIDSession;
import com.bidsdk.model.BIDSessionResponse;
import com.bidsdk.model.BIDTenantInfo;
import com.bidsdk.utils.ArrayHelper;
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;

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
				if(ret != null) {
					return ret;
				}
			}

			// load from services
			Boolean keepAlive = true;
			Map<String, Object> response = WTM.execute("get", url, WTM.defaultHeaders(), null, keepAlive);
			String responseStr = (String) response.get("response");
			int statusCode = (Integer) response.get("status");
			if (statusCode == 200) {
				Map<String, String> map = new Gson().fromJson(responseStr, Map.class);
				ret = map.get("publicKey");
				if(ret != null) {
					InMemCache.getInstance().set(cache_key, responseStr, 24*60*60*1000);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;
	}

	public static BIDSession createNewSession(BIDTenantInfo tenantInfo, String authType, String scopes,
			Map<String, Object> metadataOrNull, String journeyId) {
		BIDSession ret = null;
		try {
			
			if(journeyId == null) {
				journeyId = UUID.randomUUID().toString();
			}
		    
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
			
			System.out.println("journeyId "+ journeyId + " | Helper | Create New Session UWL 2.0 | Request body " + body);
			
			Boolean keepAlive = true;
			Map<String, Object> response = WTM.execute("put", sd.sessions + "/session/new", headers,
					new Gson().toJson(body), keepAlive);

			String responseStr = (String) response.get("response");
			int statusCode = (Integer) response.get("status");

			ret = new Gson().fromJson(responseStr, BIDSession.class);
			ret.url = sd.sessions;
			ret.status = statusCode;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDSessionResponse pollSession(BIDTenantInfo tenantInfo, String sessionId, boolean fetchProfile,
			boolean fetchDevices, Map<String, Object> eventDataOrNull, Map<String, Object> requestId, String journeyId) {

		BIDSessionResponse ret = new BIDSessionResponse();
		ret.sessionId = sessionId;
		ret.status = HttpStatus.SC_NOT_FOUND;
		try {
			
			
			if(requestId == null) {
				requestId = WTM.makeRequestId();
			}
			
			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId +  " | Helper | Poll Session UWL 2.0 | Requested event data " + eventDataOrNull);
			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);
			
            InetAddress localHost = InetAddress.getLocalHost();
            String ipAddress = localHost.getHostAddress();
            
			String sessionsPublicKey = getPublicKey(sd.sessions);
			
			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, sessionsPublicKey);
			Boolean keepAlive = true;

			//fetch session response
			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId((String) requestId.get("uuid"))), sharedKey));
			headers.put("publickey", keySet.publicKey);
			headers.put("addsessioninfo", Integer.toString(1));
			
			Map<String, Object> response = WTM.execute("get", sd.sessions + "/session/" + sessionId + "/response", headers, null, keepAlive);
			String responseStr = (String) response.get("response");
			int statusCode = (Integer) response.get("status");

			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Helper | Poll Session UWL 2.0 | Status: " +statusCode+ " Response str and status: " + responseStr);

			//if no response received.. fail here
			if (statusCode != HttpStatus.SC_OK) {
				ret.status = statusCode;
				ret.message = responseStr;
				return ret;
			}

			//response found
			ret = new Gson().fromJson(responseStr, BIDSessionResponse.class);
			ret.status = statusCode;

			if (ret.data == null) {//no data found.. error out.
				ret.status = HttpStatus.SC_UNAUTHORIZED;
				return ret;
			}

			//check session metadata for purpose
			Map<String, Object> session_metadata = ret.sessionInfo != null ? (Map<String, Object>) ret.sessionInfo.get("metadata") : null;
			String session_purpose = session_metadata != null ? (String) session_metadata.get("purpose") : null;
			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Helper | Poll Session UWL 2.0 | Session purpose: " + session_purpose);


			
			String clientSharedKey = BIDECDSA.createSharedKey(keySet.privateKey, ret.publicKey);
			String dec_data = BIDECDSA.decrypt(ret.data, clientSharedKey);
			ret.user_data = new Gson().fromJson(dec_data, Map.class); //data from mobile device.

			if (!ret.user_data.containsKey("did")) {
				ret.status = HttpStatus.SC_UNAUTHORIZED;
				return ret;
			}

			//fetch PoN data
			ret.account_data = BIDUsers.fetchUserByDID(tenantInfo, (String) ret.user_data.get("did"), fetchDevices);
			System.out.println("BIDUsers.fetchUserByDID response did " + (String) ret.user_data.get("did") + " user from mobile: " + (String) ret.user_data.get("userid")  + "   " + ret.account_data);

			List<String> ponAccounts = ret.account_data != null && ret.account_data.get("userIdList") != null ? (List<String>) ret.account_data.get("userIdList") : new ArrayList<String>();

			//check if authenticator response is authorized.
			String userid = (String) ret.user_data.get("userid");
			if (userid == null && ponAccounts.size() > 0) {
				userid = ponAccounts.get(0);
				ret.user_data.put("userid", userid);
			}

			if ((ArrayHelper.containStringEqualsIgonreCase(ponAccounts, userid))) {
				ret.isValid = true;
			} else {//this covers pon not found, ponUsers empty and ponUsers does not carry mobile user
				ret.status = HttpStatus.SC_UNAUTHORIZED;
				ret.isValid = false;
				ret.message = "Unauthorized user";
			}
			//return ret;// returning ret here should result in appropriate browser behavior

			// should we report an event
			if (session_purpose.toLowerCase().equals("authentication")) { 
				Map<String, Object> data = new HashMap<>();
				data.put("tenant_dns", tenantInfo.dns);
				data.put("tenant_tag", communityInfo.tenant.tenanttag);
				data.put("service_name", "Java Helper");
				data.put("auth_method", "qr");
				data.put("type", "event");
				data.put("event_id", UUID.randomUUID().toString());
				data.put("event_ts", System.currentTimeMillis());
				data.put("version", "v1");
				data.put("server_ip", ipAddress);
				data.put("session_id", sessionId);
				data.put("journey_id", journeyId);

				//TODO: add mobile authenticator DID & publicKey 
				
				String did = (String) ret.user_data.get("did");

				data.put("did", did);
				data.put("auth_public_key", ret.publicKey);
				
				Map<String, Object> reason = new HashMap<>();
				String eventName = ret.isValid ? "E_LOGIN_SUCCEEDED" : "E_LOGIN_FAILED";


				try {
					Object accountStr = ret.user_data.get("account");
					Map<String, Object> userData = new HashMap<>();

					if(accountStr instanceof String) {
						userData = new Gson().fromJson((String) accountStr, Map.class);
					}
					else {
						userData = (LinkedTreeMap<String, Object>) accountStr;
					}
					
					data.put("user_id", ret.user_data.get("userid"));				
				}
				catch (Exception e) {
					e.printStackTrace();
					System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Unable to get accountData from mobile authenticator payload | " 
					+ ret.user_data.get("account"));
				}
				// Overriding event data
				if (eventDataOrNull != null) {
					data.putAll(eventDataOrNull);
				}

				if (!ret.isValid) {
					reason.put("reason", "User not found in PON data");
					data.put("login_state", "FAILED");
					data.put("eventData", reason);
				}	

				System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " |completed Event Logging  | " + eventName + "Payload || "+new Gson().toJson(data));
				
				BIDReports.logEventAsync(tenantInfo, eventName, data, requestId);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;

	}
}
