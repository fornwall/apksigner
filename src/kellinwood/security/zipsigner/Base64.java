/*
 * Copyright (C) 2010 Ken Ellinwood.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package kellinwood.security.zipsigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.spongycastle.util.encoders.Base64Encoder;

/** Base64 encoding handling in a portable way across Android and JSE. */
public class Base64 {

	public static String encode(byte[] data) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			new Base64Encoder().encode(data, 0, data.length, baos);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return new String(baos.toByteArray());
	}

	public static byte[] decode(String data) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			new Base64Encoder().decode(data, baos);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
		return baos.toByteArray();
	}
}