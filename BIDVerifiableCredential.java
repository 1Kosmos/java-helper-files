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
import java.util.List;
import java.util.Map;

public class BIDVerifiableCredential {

	private static String getPublicKey(BIDTenantInfo tenantInfo) {
		String ret = null;
		try {
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);
			String url = sd.vcs + "/publickeys";

			String cache_key = url;
			String cache_str = InMemCache.getInstance().get(cache_key);
			if (cache_str != null) {
				Map<String, String> map = new Gson().fromJson(cache_str, Map.class);
				ret = map.get("publicKey");
				return ret;
			}

			// load from services
			Map<String, Object> response = WTM.execute("get", url, WTM.defaultHeaders(), null);
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

	public static BIDDocumentVCResponse requestVCForID(BIDTenantInfo tenantInfo, String type, BIDDLObjectData document,
			String userDid, String userPublickey, String userUrn) {
		BIDDocumentVCResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(tenantInfo);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("document", document);
			body.put("did", userDid);
			body.put("publicKey", userPublickey);
			body.put("userURN", userUrn);

			Map<String, Object> response = WTM
					.execute(
							"post", sd.vcs + "/tenant/" + communityInfo.tenant.id + "/community/"
									+ communityInfo.community.id + "/vc/from/document/" + type,
							headers, new Gson().toJson(body));

			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDDocumentVCResponse.class);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDPayloadVCResponse requestVCForPayload(BIDTenantInfo tenantInfo, String type, BIDIssuerData issuer,
			BIDEmploymentInfoData info, String userDid, String userPublickey, String userUrn) {
		BIDPayloadVCResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(tenantInfo);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("info", info);
			body.put("did", userDid);
			body.put("publicKey", userPublickey);
			body.put("userURN", userUrn);
			body.put("issuer", issuer);

			Map<String, Object> response = WTM
					.execute(
							"post", sd.vcs + "/tenant/" + communityInfo.tenant.id + "/community/"
									+ communityInfo.community.id + "/vc/from/payload/" + type,
							headers, new Gson().toJson(body));

			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDPayloadVCResponse.class);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDVerifiedVCResponse verifyCredential(BIDTenantInfo tenantInfo, Map<String, Object> vc) {
		BIDVerifiedVCResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(tenantInfo);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("vc", vc);

			Map<String, Object> response = WTM.execute("post", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vc/verify", headers, new Gson().toJson(body));

			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDVerifiedVCResponse.class);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDRequestVPResponse requestVPForCredentials(BIDTenantInfo tenantInfo, List<BIDRequestVPData> vcs) {
		BIDRequestVPResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(tenantInfo);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("vcs", vcs);

			Map<String, Object> response = WTM.execute("post", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vp/create", headers, new Gson().toJson(body));

			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDRequestVPResponse.class);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDVerifiedVPResponse verifyPresentation(BIDTenantInfo tenantInfo, Map<String, Object> vp) {
		BIDVerifiedVPResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(tenantInfo);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("vp", vp);

			Map<String, Object> response = WTM.execute("post", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vp/verify", headers, new Gson().toJson(body));

			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDVerifiedVPResponse.class);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDVCStatusResponse getVcStatusById(BIDTenantInfo tenantInfo, String vcId) {
		BIDVCStatusResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(tenantInfo);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> response = WTM.execute("get", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vc/" + vcId + "/status", headers, null);

			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDVCStatusResponse.class);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}
}
