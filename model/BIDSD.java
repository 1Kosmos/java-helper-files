/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk.model;

import com.google.gson.Gson;

public class BIDSD {

    public String sessions;
    public String licenses;
    public String global_caas;
    public String adminconsole;
    public String user_management;
    public String authn;
    public String authz;
    public String acr;
    public String reports
    public String events;
    public String webauthn;
    public String docuverify;
    public String vcs;
    public String oauth2;

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }

}
