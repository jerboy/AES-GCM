import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AES对称加密工具类
 * 
 *
 */
public class AESUtils {

	private static final Logger logger = LoggerFactory.getLogger(AESUtils.class);

	private static final String KEY_ALGORITHM = "AES";
	private static final String DEFAULT_CIPHER_ALGORITHM = "AES/GCM/PKCS5Padding";;// 默认的加密算法

	/**
	 * AES 加密操作
	 *
	 * @param content     待加密内容
	 * @param encryptPass 加密密码
	 * @return 返回Base64转码后的加密数据
	 */
	public static String encrypt(String content, String encryptPass) {
		try {
			Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
			cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(encryptPass));
			byte[] iv = cipher.getIV();
			assert iv.length == 12;
			byte[] encryptData = cipher.doFinal(content.getBytes());
			assert encryptData.length == content.getBytes().length + 16;
			byte[] message = new byte[12 + content.getBytes().length + 16];
			System.arraycopy(iv, 0, message, 0, 12);
			System.arraycopy(encryptData, 0, message, 12, encryptData.length);
			return Base64.encodeBase64String(message);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException
				| BadPaddingException e) {
			logger.error(e.getMessage(), e);
		}
		return null;
	}

	/**
	 * AES 解密操作
	 *
	 * @param base64Content
	 * @param encryptPass
	 * @return
	 */
	public static String decrypt(String base64Content, String encryptPass) {
		byte[] content = Base64.decodeBase64(base64Content);
		if (content.length < 12 + 16)
			throw new IllegalArgumentException();
		GCMParameterSpec params = new GCMParameterSpec(128, content, 0, 12);
		try {
			Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE, getSecretKey(encryptPass), params);
			byte[] decryptData = cipher.doFinal(content, 12, content.length - 12);
			return new String(decryptData);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			logger.error(e.getMessage(), e);
		}
		return null;
	}

	/**
	 * 生成加密秘钥
	 *
	 * @return
	 * @throws NoSuchAlgorithmException
	 */
	private static SecretKeySpec getSecretKey(String encryptPass) throws NoSuchAlgorithmException {
		KeyGenerator kg = KeyGenerator.getInstance(KEY_ALGORITHM);
		// 初始化密钥生成器，AES要求密钥长度为128位、192位、256位
		kg.init(128, new SecureRandom(encryptPass.getBytes()));
		SecretKey secretKey = kg.generateKey();
		return new SecretKeySpec(secretKey.getEncoded(), KEY_ALGORITHM);// 转换为AES专用密钥
	}

	public static void main(String[] args) {
		String s = "65c86251eeeed0638be6e737a136dd3060097c4094d6f2d7dc56824670519022&EBD0B5D2-F4E7-453A-9E16-01AE8F6E2977&Mozilla/5.0 (iPhone; CPU iPhone OS 12_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148";
		String pass = "EBD0B5D2-F4E7-453A-9E16-01AE8F6E2977";
		String encoded = encrypt(s, pass);
		logger.info("加密之前：{}", s);
		logger.info("加密结果：{}", encoded);
		logger.info("解密结果：{}", decrypt(encoded, pass));
	}
}
