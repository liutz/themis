/*
* Copyright (c) 2015 Cossack Labs Limited
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

package com.cossacklabs.themis.test;

import java.util.Arrays;
import java.util.Random;
import java.nio.charset.StandardCharsets;

import com.cossacklabs.themis.SecureCell;
import com.cossacklabs.themis.SecureCellData;

import android.test.AndroidTestCase;
import android.util.Base64;
import android.util.Log;

public class SecureCellTest extends AndroidTestCase {
	
	static final int MAX_TEST_DATA = 1024;
	Random rand = new Random();
	
	private byte[] generateTestData() {
		int dataLength = 0;
		
		do {
			dataLength = rand.nextInt(MAX_TEST_DATA);
		} while (0 == dataLength);
		
		byte[] data = new byte[dataLength];
		rand.nextBytes(data);
		
		return data;
	}

	@Override
	public void runTest() {
		try {
			testBase64Decoding();
			testSeal();
			testSealWithStrings();
			testTokenProtect();
			testContextImprint();
		} catch (Exception e) {
			String failMessage = e.getClass().getCanonicalName();
			
			if (null != e.getMessage()) {
				failMessage += ": " + e.getMessage();
			}
			
			fail(failMessage);
		}
	}
	
	void testBase64Decoding()throws Exception {
		String charset = StandardCharsets.UTF_8.name();
		String normalString = "i'm super normal string hello";
		byte[] normalData = normalString.getBytes(charset);
		String base64Normal = Base64.encodeToString(normalData, Base64.NO_WRAP);

		byte[] base64Data = Base64.decode(base64Normal, Base64.NO_WRAP);
		String base64Decoded = new String(base64Data, charset);

		Log.d("SMC", "normalString = " + normalString + "\nbase64Normal = " + base64Normal + "\nbase64Decoded = " + base64Decoded);
		assertTrue(normalString.equals(base64Decoded));
	}

	void testSeal() throws Exception {
		String key = "seal key";
		String context = "seal context";
		byte[] data = generateTestData();
		
		SecureCell cell = new SecureCell(key);
		assertNotNull(cell);

		SecureCellData protectedData = cell.protect(context, data);
		
		assertNotNull(protectedData);
		assertNotNull(protectedData.getProtectedData());
		assertNull(protectedData.getAdditionalData());
		
		assertTrue(protectedData.getProtectedData().length > data.length);
		
		cell = new SecureCell(key);
		byte[] unprotectedData = cell.unprotect(context, protectedData);
		assertNotNull(unprotectedData);
		
		assertTrue(Arrays.equals(data, unprotectedData));
	}

	void testSealWithStrings() throws Exception {
		String key = "seal key";
		String context = "seal context";
		String stringToEncrypt = "some random data to encrypt";
		String charsetUTF8 = StandardCharsets.UTF_8.name();
		String charsetUTF16 = StandardCharsets.UTF_16.name();

		runTestSealWithStrings(key, context, stringToEncrypt, charsetUTF8);
		runTestSealWithStrings(key, context, stringToEncrypt, charsetUTF16);

		runTestSealWithStrings(key, null, stringToEncrypt, charsetUTF8);
		runTestSealWithStrings(key, null, stringToEncrypt, charsetUTF16);
	}

    void runTestSealWithStrings(String key, String context, String stringToEncrypt, String charset) throws Exception {
    	String encryptedString = encryptStringFromExternalSource(key, context, stringToEncrypt, charset);
		String decryptedString = decryptStringFromExternalSource(key, context, encryptedString, charset);
		assertTrue(decryptedString.equals(stringToEncrypt));
    }

    String encryptStringFromExternalSource(String key, String context, String originalString, String charset) throws Exception {
	    byte[] data = originalString.getBytes(charset);

		SecureCell cell = new SecureCell(key);
		assertNotNull(cell);

		SecureCellData protectedData = cell.protect(context, data);
		
		assertNotNull(protectedData);
		assertNotNull(protectedData.getProtectedData());
		assertNull(protectedData.getAdditionalData());
		
		assertTrue(protectedData.getProtectedData().length > data.length);

		// encrypted data to base64
	    String protectedDataBytesString = Base64.encodeToString(protectedData.getProtectedData(), Base64.NO_WRAP);
	    return protectedDataBytesString;
    }

    String decryptStringFromExternalSource(String key, String context, String stringToDecrypt, String charset) throws Exception {
		SecureCell cell = new SecureCell(key);
		assertNotNull(cell);

	    byte[] encryptedDataBytesFromString = Base64.decode(stringToDecrypt, Base64.NO_WRAP);
	    SecureCellData encryptedDataFromString = new SecureCellData(encryptedDataBytesFromString, null);

		// try to decrypted converted 
        byte[] unprotectedDataFromString = cell.unprotect(context, encryptedDataFromString);
        assertNotNull(unprotectedDataFromString);

        String unprotectedString = new String(unprotectedDataFromString, charset);
        return unprotectedString;
    }
	
	void testTokenProtect() throws Exception {
		String key = "token protect key";
		String context = "token protect context";
		byte[] data = generateTestData();
		
		SecureCell cell = new SecureCell(key, SecureCell.MODE_TOKEN_PROTECT);
		assertNotNull(cell);

		SecureCellData protectedData = cell.protect(key, context, data);
		
		assertNotNull(protectedData);
		assertNotNull(protectedData.getProtectedData());
		assertNotNull(protectedData.getAdditionalData());
		
		assertTrue(protectedData.getProtectedData().length == data.length);
		
		cell = new SecureCell(key, SecureCell.MODE_TOKEN_PROTECT);
		byte[] unprotectedData = cell.unprotect(context, protectedData);
		
		assertTrue(Arrays.equals(data, unprotectedData));
	}
	
	void testContextImprint() throws Exception {
		String key = "context imprint key";
		String context = "context imprint context";
		byte[] data = generateTestData();
		
		SecureCell cell = new SecureCell(key, SecureCell.MODE_CONTEXT_IMPRINT);
		assertNotNull(cell);

		SecureCellData protectedData = cell.protect(context, data);
		
		assertNotNull(protectedData);
		assertNotNull(protectedData.getProtectedData());
		assertNull(protectedData.getAdditionalData());
		
		assertTrue(protectedData.getProtectedData().length == data.length);
		
		cell = new SecureCell(key, SecureCell.MODE_CONTEXT_IMPRINT);
		byte[] unprotectedData = cell.unprotect(context, protectedData);
		
		assertTrue(Arrays.equals(data, unprotectedData));
	}
}