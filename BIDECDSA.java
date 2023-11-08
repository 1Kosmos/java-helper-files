/**
 * Copyright (c) 2018, 1Kosmos Inc. All rights reserved.
 * Licensed under 1Kosmos Open Source Public License version 1.0 (the "License");
 * You may not use this file except in compliance with the License. 
 * You may obtain a copy of this license at 
 *    https://github.com/1Kosmos/1Kosmos_License/blob/main/LICENSE.txt
 */
package com.bidsdk;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.KeyAgreement;

import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.WalletFile;
import org.web3j.protocol.ObjectMapperFactory;

import com.bidsdk.model.BIDKeyPair;
import com.bidsdk.utils.EncryptDecryptLogic;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;


public class BIDECDSA {

    private static final String mDefaultDerivativePath = "m/44'/60'/0'/0/0";//default derivative path for ethereum wallet
    public static BIDKeyPair generateKeyPair() {
        DeterministicSeed deterministicSeed = new DeterministicSeed(new SecureRandom(), 128, "");
        String[] pathArray = mDefaultDerivativePath.split("/");

        byte[] seedBytes = deterministicSeed.getSeedBytes();
        List<String> mnemonic = deterministicSeed.getMnemonicCode();

        if (seedBytes == null)
            return null;

        DeterministicKey deterministicKey = HDKeyDerivation.createMasterPrivateKey(seedBytes);

        for (int i = 1; i < pathArray.length; i++) {
            ChildNumber childNumber;
            if (pathArray[i].endsWith("'")) {
                int number = Integer.parseInt(pathArray[i].substring(0, pathArray[i].length() - 1));
                childNumber = new ChildNumber(number, true);
            } else {
                int number = Integer.parseInt(pathArray[i]);
                childNumber = new ChildNumber(number, false);
            }
            deterministicKey = HDKeyDerivation.deriveChildKey(deterministicKey, childNumber);
        }

        ECKeyPair keyPair = ECKeyPair.create(deterministicKey.getPrivKeyBytes());
        BigInteger privateKeyInt = keyPair.getPrivateKey();
        BigInteger publicKeyInt = keyPair.getPublicKey();

        BIDKeyPair ret = null;
        try {
            WalletFile walletFile = org.web3j.crypto.Wallet.createLight("", keyPair);
            ObjectMapper objectMapper = ObjectMapperFactory.getObjectMapper();
            try {
				String jsonStr = objectMapper.writeValueAsString(walletFile);
			} catch (JsonProcessingException e) {
				e.printStackTrace();
			}
            byte[] publicKeyByte = null;
            if (publicKeyInt.toByteArray().length > 64) {
                publicKeyByte = Arrays.copyOfRange(publicKeyInt.toByteArray(), 1, publicKeyInt.toByteArray().length);
            } else {
                publicKeyByte = publicKeyInt.toByteArray();
            }

            Base64.Encoder encoder = Base64.getEncoder();

            ret = new BIDKeyPair();
            ret.privateKey = encoder.encodeToString(privateKeyInt.toByteArray());
            ret.publicKey = encoder.encodeToString(publicKeyByte);
// don't need mnemonic and did at this time mnemonic, walletFile.getAddress());

        } catch (Exception e) {
            e.printStackTrace();
        }
        return ret;
    }

    public static String encrypt(String value, String key) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        EncryptDecryptLogic encryptDecryptLogic = new EncryptDecryptLogic();
        return encryptDecryptLogic.ecdsaHelper("encrypt", value, key);
    }

    public static String decrypt(String value, String key) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        EncryptDecryptLogic encryptDecryptLogic = new EncryptDecryptLogic();
        return encryptDecryptLogic.ecdsaHelper("decrypt", value, key);
    }

    public static String createSharedKey(String prKey, String pbKey) throws Exception {
        byte[] privateKeyStr = Base64.getDecoder().decode(prKey.getBytes());
        byte[] publicKeyStr = Base64.getDecoder().decode(pbKey.getBytes());
        PrivateKey privateKey = toECPrivateKey(privateKeyStr);
        PublicKey publicKey = toEcPublicKey(publicKeyStr);
        KeyAgreement ka1 = null;
        ka1 = KeyAgreement.getInstance("ECDH");
        ka1.init(privateKey);
        ka1.doPhase(publicKey, true);
        byte[] sharedSecret1 = ka1.generateSecret();
        return Base64.getEncoder().encodeToString(sharedSecret1);
    }

    private static PrivateKey toECPrivateKey(byte[] privateKeyStr) throws Exception {
        BigInteger privKey = new BigInteger(privateKeyStr);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECNamedCurveSpec curveSpec = new ECNamedCurveSpec("secp256k1", params.getCurve(), params.getG(),
                params.getN());
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(privKey, curveSpec);
        return keyFactory.generatePrivate(keySpec);
    }

    private static PublicKey toEcPublicKey(byte[] publicKeyByte) throws Exception {
        String publicKeyStr = byteArrayToHex(publicKeyByte);
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp256k1");
        ECNamedCurveSpec curveSpec = new ECNamedCurveSpec("secp256k1", params.getCurve(), params.getG(),
                params.getN());
        // This is the part how to generate ECPoint manually from public key string.\
        String pubKeyX = publicKeyStr.substring(0, publicKeyStr.length() / 2);
        String pubKeyY = publicKeyStr.substring(publicKeyStr.length() / 2);
        ECPoint ecPoint = new ECPoint(new BigInteger(pubKeyX, 16), new BigInteger(pubKeyY, 16));
        ECParameterSpec params2 = EC5Util.convertSpec(curveSpec.getCurve(), params);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(ecPoint, params2);
        KeyFactory factory = KeyFactory.getInstance("ECDSA");
        return factory.generatePublic(keySpec);
    }

    private static String byteArrayToHex(byte[] bytes) {
        char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }




}
