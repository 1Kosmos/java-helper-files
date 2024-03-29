/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk.model;

import java.util.Map;

import com.google.gson.Gson;

public class BIDSessionResponse {
	public String sessionId;
	public String data;
	public String appid;
	public String ial;
	public String publicKey;
	public long createdTS;
	public String createdDate;
	public String eventData;
	public int status;
	public String message;
	public Map<String, Object> user_data;
	public Map<String, Object> account_data;
	public Map<String, Object> sessionInfo;
	public boolean isValid = false;

	@Override
	public String toString() {
		return new Gson().toJson(this);
	}
}
