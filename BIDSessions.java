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
import com.bidsdk.utils.ArrayHelper;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;

import java.net.InetAddress;
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
			Map<String, Object> metadataOrNull, String journeyId) {
		BIDSession ret = null;
		try {
			
			if(journeyId == null) {
				System.out.println("journeyId "+ journeyId + " | Create New Session UWL 2.0 | Creating new journeyId");
				journeyId = UUID.randomUUID().toString();
			}
			
			System.out.println("journeyId "+ journeyId + " | "+"Create New Session UWL 2.0 | tenant DNS " + tenantInfo.dns);
		    
			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			System.out.println("journeyId "+ journeyId + " | Helper | Create New Session UWL 2.0 | Fetched community from adminconsole");
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);
			System.out.println("journeyId "+ journeyId + " | Helper | Create New Session | Fetched SD | session URL " + sd.sessions);

			String sessionsPublicKey = getPublicKey(sd.sessions);
			System.out.println("journeyId "+ journeyId + " | Helper | Create New Session | Fetched session public key " + sessionsPublicKey);

			Map<String, Object> origin = new HashMap<>();
			origin.put("tag", communityInfo.tenant.tenanttag);
			origin.put("url", sd.adminconsole);
			origin.put("communityName", communityInfo.community.name);
			origin.put("communityId", communityInfo.community.id);
			origin.put("authPage", "blockid://authenticate");

			System.out.println("journeyId "+ journeyId + " | "+"Create New Session UWL 2.0 | Preparing request params");
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

			System.out.println("journeyId "+ journeyId + " | Helper | Create New Session UWL 2.0 | Response str and status: " + responseStr + " | status "+ statusCode );
			ret = new Gson().fromJson(responseStr, BIDSession.class);
			ret.url = sd.sessions;
			ret.status = statusCode;
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("journeyId "+ journeyId + " | Helper | Create New Session UWL 2.0 | Return Response ");
		return ret;
	}

	public static BIDSessionResponse pollSession(BIDTenantInfo tenantInfo, String sessionId, boolean fetchProfile,
			boolean fetchDevices, Map<String, Object> eventDataOrNull, Map<String, Object> requestId, String journeyId) {
		BIDSessionResponse ret = null;
		try {
			
			if(journeyId == null) {
				System.out.println("journeyId "+ journeyId + " | Create New Session UWL 2.0 | Creating new journeyId");
				journeyId = UUID.randomUUID().toString();
			}
			
			if(requestId == null) {
				System.out.println("journeyId "+ journeyId + " | RequestId " + requestId +  " | Create New Session UWL 2.0 | Creating new requestId");
				requestId = WTM.makeRequestId();
			}
			
			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId +  " | Helper | Poll Session UWL 2.0 | Requested event data " + eventDataOrNull);
			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId +  "| Helper | Poll Session UWL 2.0 | Fetched community from adminconsole");
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);
			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + "| Helper | Poll Session UWL 2.0 | Fetched SD | Session URL: " + sd.sessions);
			
            InetAddress localHost = InetAddress.getLocalHost();
            String ipAddress = localHost.getHostAddress();
            
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
			
			Map<String, Object> reason = new HashMap<>();
			String eventName = "E_LOGIN_FAILED";
			
			String sessionsPublicKey = getPublicKey(sd.sessions);
			System.out.println("RequestId " + requestId + " | " + sessionId + "| Helper | Poll Session UWL 2.0 | Fetched session public key " + sessionsPublicKey);
			
			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, sessionsPublicKey);
			Boolean keepAlive = true;

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId((String) requestId.get("uuid"))), sharedKey));
			headers.put("publickey", keySet.publicKey);
			headers.put("addsessioninfo", Integer.toString(1));
			
			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + "| Helper | Poll Session UWL 2.0 | Fetching session info ");
			Map<String, Object> sessionInfoResponse = WTM.execute("get", sd.sessions + "/session/" + sessionId,
					headers, null, keepAlive);

			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + "| Helper | Poll Session UWL 2.0 | Fetching session response ");
			Map<String, Object> response = WTM.execute("get", sd.sessions + "/session/" + sessionId + "/response",
					headers, null, keepAlive);

			String responseStr = (String) response.get("response");
			int statusCode = (Integer) response.get("status");

			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Helper | Poll Session UWL 2.0 | Status: " +statusCode+ " Response str and status: " + responseStr);
			if (statusCode == HttpStatus.SC_NOT_FOUND) {
				ret = new BIDSessionResponse();
				ret.status = statusCode;
				ret.message = responseStr;
				return ret;
			}

			if (statusCode != HttpStatus.SC_OK) {
				String sessionInfoStr= (String) sessionInfoResponse.get("response");
				Map<String, Object> sessionInfoRes  = new Gson().fromJson(sessionInfoStr, Map.class);
				Map<String, Object> metadata = sessionInfoRes != null
						? (Map<String, Object>) sessionInfoRes.get("metadata")
						: null;
				System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " Status not 200 | sessionInfoRes " + sessionInfoRes);
				
				if(metadata != null && ((String) metadata.get("purpose")).equals("authentication")) {
					
					// Overriding event data
					if (eventDataOrNull != null) {
						data.putAll(eventDataOrNull);
					}
					
					reason.put("reason", responseStr);
					data.put("login_state", "FAILED");
					data.put("eventData", reason);
					System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Helper | Poll Session UWL 2.0 | Logging fail event | reason: " + responseStr);
					BIDReports.logEvent(tenantInfo, eventName, data, requestId);
				}
				ret = new BIDSessionResponse();
				ret.status = statusCode;
				ret.message = responseStr;
				return ret;
			}

			ret = new Gson().fromJson(responseStr, BIDSessionResponse.class);
			ret.status = statusCode;

			if (ret.data != null) {
				String clientSharedKey = BIDECDSA.createSharedKey(keySet.privateKey, ret.publicKey);
				String dec_data = BIDECDSA.decrypt(ret.data, clientSharedKey);
				ret.user_data = new Gson().fromJson(dec_data, Map.class);
			}

			if (ret != null && ret.data != null && ret.user_data.containsKey("did") && fetchProfile) {
				System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Helper | Poll Session UWL 2.0 | Calling Fetch user by DID");
				ret.account_data = BIDUsers.fetchUserByDID(tenantInfo, (String) ret.user_data.get("did"), fetchDevices);
			}

			Map<String, Object> metadata = null;
			String purpose = null;

			if(ret.sessionInfo != null) {
				 metadata = (Map<String, Object>) ret.sessionInfo.get("metadata");
				 purpose = (String) metadata.get("purpose");
			}

			System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Helper | Poll Session UWL 2.0 | Session purpose: " + purpose);
			if (metadata != null && ((String) purpose).toLowerCase().equals("authentication")) {

				String did = (String) ret.user_data.get("did");

				Map<String, Object> userData = (Map<String, Object>) ret.user_data.get("account");
				System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | Helper |  Poll Session UWL 2.0 | Prepare event data");
				Map<String, Object> account = new HashMap<>();
				account.put("username", userData.get("username"));
				account.put("uid", userData.get("uid"));
				account.put("authmoduleid", userData.get("authmoduleid"));
				account.put("source", userData.get("source"));
				data.put("user_id", ret.user_data.get("userid"));				

				// Overriding event data
				if (eventDataOrNull != null) {
					data.putAll(eventDataOrNull);
				}
	
				// verifying a user account is linked to the ProofOfName entry on the tenant or not
				if (ret.account_data == null || !(ArrayHelper.containString((List<String>) ret.account_data.get("userIdList"), (String) userData.get("username")))) {
					reason.put("reason", "PON data not found");
					data.put("login_state", "FAILED");
					data.put("eventData", reason);
					System.out.println("journeyId "+ journeyId + " | Helper | Poll Session UWL 2.0 | Logging fail event | reason: " + new Gson().toJson(reason));
					BIDReports.logEvent(tenantInfo, eventName, data, requestId);
					return ret;
				}
				System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + "| Helper | Poll Session UWL 2.0 | Fetching user account by did");
				Map<String, Object> userInfo = BIDUsers.fetchUserAccountsByDID(tenantInfo, did, true, true, account);
				Map<String, Object> deviceData = (Map<String, Object>) userInfo.get("device");

				List<Object> users = (List<Object>) userInfo.get("users");
				
				if (!users.isEmpty() && users.size() == 1) {
					System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + "| Helper | Poll Session UWL 2.0 | one user account found ");
					Map<String, Object> user = (Map<String, Object>) users.get(0);

					String status = (String) user.get("status");
					Boolean isDisabled = (Boolean) user.get("disabled");
					Boolean isLocked = (Boolean) user.get("isLocked");

					data.put("user_status", status);
					data.put("user_email", user.get("email"));
					data.put("user_firstname", user.get("firstname"));
					data.put("user_lastname", user.get("lastname"));

					eventName = (status.equals("active") && !isDisabled && !isLocked) ? "E_LOGIN_SUCCEEDED"
							: "E_LOGIN_FAILED";

					data.put("login_state", "SUCCESS");

					if (isLocked) {
						data.put("login_state", "FAILED");
						reason.put("reason", "The user account has been locked");
					} else if (!status.equals("active")) {
						data.put("login_state", "FAILED");
						reason.put("reason", "The user account has not been active");
					} else if (isDisabled) {
						data.put("login_state", "FAILED");
						reason.put("reason", "The user account has been disabled");
					}

				} else {
					data.put("login_state", "FAILED");
					reason.put("reason", (users.size() != 1) ? "Multiple Users found" : "User not Found");
					System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + "| Helper | Poll Session UWL 2.0 | Logging fail event | reason: " + new Gson().toJson(reason));					
				}

				// Device Data
				data.put("device_id", deviceData.get("uid"));
				data.put("auth_device_os", deviceData.get("os"));
				data.put("auth_device_name", deviceData.get("deviceName"));
				data.put("auth_device_app_name", deviceData.get("authenticatorName"));
				data.put("auth_device_app_version", deviceData.get("authenticatorVersion"));
				data.put("auth_device_latitude", deviceData.get("locLat"));
				data.put("auth_device_longitude", deviceData.get("locLon"));

				if (!reason.isEmpty()) {
					data.put("eventData", reason);
				}

				System.out.println("journeyId "+ journeyId + " | RequestId " + requestId + " | " + sessionId + " | Helper | Event Logging ");
				BIDReports.logEvent(tenantInfo, eventName, data, requestId);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("RequestId " + requestId + " | " + sessionId + " | Helper | Return Response ");
		return ret;

	}
}
