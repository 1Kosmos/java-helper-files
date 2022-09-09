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

public class BIDDLObjectData {
	public String type;
	public String documentType;
	public String category;
	public String proofedBy;
	public String documentId;
	public String id;
	public String firstName;
	public String lastName;
	public String familyName;
	public String middleName;
	public String givenName;
	public String fullName;
	public String dob;
	public String doe;
	public String doi;
	public String face;
	public String image;
	public String imageBack;
	public String gender;
	public String height;
	public String eyeColor;
	public String street;
	public String city;
	public String restrictionCode;
	public String residenceCity;
	public String state;
	public String country;
	public String zipCode;
	public String residenceZipCode;
	public String county;
	public String classificationCode;
	public String complianceType;
	public String placeOfBirth;

    @Override
    public String toString() {
        return new Gson().toJson(this);
    }
}
