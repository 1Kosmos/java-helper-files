/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import com.bidsdk.model.*;
import com.bidsdk.model.BIDVerifiableCredentials.BIDDocumentResponse;
import com.bidsdk.model.BIDVerifiableCredentials.BIDPayloadResponse;
import com.bidsdk.model.BIDVerifiableCredentials.BIDVCStatusResponse;
import com.bidsdk.model.BIDVerifiableCredentials.BIDVerifiedResponse;
import com.bidsdk.model.BIDVerifiablePresentation.BIDIssuedVPResponse;
import com.bidsdk.model.BIDVerifiablePresentation.BIDVerifiedVPResponse;
import com.bidsdk.utils.InMemCache;
import com.bidsdk.utils.WTM;
import com.google.gson.Gson;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BIDVerifiableCredential {

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

	public static BIDDocumentResponse requestVCForID(BIDTenantInfo tenantInfo, String type,
			Map<String, String> document, String userDid, String userPublickey, String userUrn) {
		BIDDocumentResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(sd.vcs);

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

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDDocumentResponse.class);
			ret.code = statusCode;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDPayloadResponse requestVCForPayload(BIDTenantInfo tenantInfo, String type,
			Map<String, Object> issuer, Map<String, Object> info, String userDid, String userPublickey,
			String userUrn) {
		BIDPayloadResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(sd.vcs);

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

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDPayloadResponse.class);
			ret.code = statusCode;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDVerifiedResponse verifyCredential(BIDTenantInfo tenantInfo, Map<String, Object> vc) {
		BIDVerifiedResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(sd.vcs);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("vc", vc);

			Map<String, Object> response = WTM.execute("post", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vc/verify", headers, new Gson().toJson(body));

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDVerifiedResponse.class);
			ret.code = statusCode;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDIssuedVPResponse requestVPForCredentials(BIDTenantInfo tenantInfo, List<BIDRequestVPData> vcs,
			Boolean createShareUrl) {
		BIDIssuedVPResponse ret = null;
		try {

			BIDCommunityInfo communityInfo = BIDTenant.getInstance().getCommunityInfo(tenantInfo);
			BIDKeyPair keySet = BIDTenant.getInstance().getKeySet();
			String licenseKey = tenantInfo.licenseKey;
			BIDSD sd = BIDTenant.getInstance().getSD(tenantInfo);

			String vcsPublicKey = getPublicKey(sd.vcs);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("vcs", vcs);
			body.put("createShareUrl", createShareUrl);

			Map<String, Object> response = WTM.execute("post", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vp/create", headers, new Gson().toJson(body));

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDIssuedVPResponse.class);
			ret.code = statusCode;

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

			String vcsPublicKey = getPublicKey(sd.vcs);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> body = new HashMap<>();
			body.put("vp", vp);

			Map<String, Object> response = WTM.execute("post", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vp/verify", headers, new Gson().toJson(body));

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDVerifiedVPResponse.class);
			ret.code = statusCode;

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

			String vcsPublicKey = getPublicKey(sd.vcs);

			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(WTM.makeRequestId()), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> response = WTM.execute("get", sd.vcs + "/tenant/" + communityInfo.tenant.id
					+ "/community/" + communityInfo.community.id + "/vc/" + vcId + "/status", headers, null);

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");
			ret = new Gson().fromJson(responseStr, BIDVCStatusResponse.class);
			ret.code = statusCode;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static Map<String, Object> getVPWithDownloadUri(String licenseKey, BIDKeyPair keySet, String downloadUri,
			Map<String, Object> requestID) {
		Map ret = null;
		try {
			URI url = new URI(downloadUri);

			String serviceUrl = "https://" + url.getHost() + "/vcs";
			String vcsPublicKey = getPublicKey(serviceUrl);
			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(requestID), sharedKey));
			headers.put("publickey", keySet.publicKey);

			Map<String, Object> response = WTM.execute("get", downloadUri, headers, null);

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");

			ret = new Gson().fromJson(responseStr, Map.class);
			if (ret.get("data") != null) {
				String clientSharedKey = BIDECDSA.createSharedKey(keySet.privateKey, (String) ret.get("publicKey"));
				String dec_data = BIDECDSA.decrypt((String) ret.get("data"), clientSharedKey);
				ret = new Gson().fromJson(dec_data, Map.class);
			}

			ret.put("code", statusCode);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}

	public static BIDVerifiedVPResponse verifyVPWithDownloadUri(String licenseKey, BIDKeyPair keySet,
			String downloadUri, Map<String, Object> vp, Map<String, Object> requestID) {
		BIDVerifiedVPResponse ret = null;
		try {
			URI url = new URI(downloadUri);
			String serviceUrl = "https://" + url.getHost() + "/vcs";
			String vcsPublicKey = getPublicKey(serviceUrl);
			String sharedKey = BIDECDSA.createSharedKey(keySet.privateKey, vcsPublicKey);

			Map<String, String> headers = WTM.defaultHeaders();
			headers.put("licensekey", BIDECDSA.encrypt(licenseKey, sharedKey));
			headers.put("requestid", BIDECDSA.encrypt(new Gson().toJson(requestID), sharedKey));
			headers.put("publickey", keySet.publicKey);

			ArrayList<Object> verifiableCredential = (ArrayList<Object>) vp.get("verifiableCredential");

			Map<String, Object> firstVC = (Map<String, Object>) verifiableCredential.get(0);

			Map<String, Object> body = new HashMap<>();
			body.put("vp", vp);

			String tenantId = ((Map<String, String>) firstVC.get("issuer")).get("tenantId");
			String communityId = ((Map<String, String>) firstVC.get("issuer")).get("communityId");

			Map<String, Object> response = WTM.execute("post",
					serviceUrl + "/tenant/" + tenantId + "/community/" + communityId + "/vp/verify", headers,
					new Gson().toJson(body));

			int statusCode = (Integer) response.get("status");
			String responseStr = (String) response.get("response");

			ret = new Gson().fromJson(responseStr, BIDVerifiedVPResponse.class);
			ret.code = statusCode;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return ret;
	}
}
