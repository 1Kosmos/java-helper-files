/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk.model;

import com.google.gson.Gson;

public class BIDTokenResponse {

	public String access_token;
	public int expires_in;
	public String id_token;
	public String refresh_token;
	public String scope;
	public String token_type;
	public int status;
	public String error;
	public String error_description;

	@Override
	public String toString() {
		return new Gson().toJson(this);
	}

}
