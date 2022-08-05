package security;

import java.security.Key;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import lombok.extern.log4j.Log4j;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * @Desc AES加解密工具类
 * @author zhuxianfei
 * @date 2022/8/5 9:54
 */
@Log4j
public class AESSecurity {

    public static String CIPHER_ALGORITHM = "AES";


    public static Key getSecretKey(String key) throws Exception {
        try {
            if (key == null) {
                key = "";
            }
            KeyGenerator _generator = KeyGenerator.getInstance("AES");
            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(key.getBytes());
            _generator.init(128, secureRandom);
            return _generator.generateKey();
        } catch (Exception e) {
            log.error(" 初始化密钥出现异常 ");
            throw new RuntimeException(" 初始化密钥出现异常 ");
        }
    }

    public static String encrypt(String data, String key) throws Exception {
        if (key == null) {
            key = "";
        }
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(key.getBytes("UTF-8"));
        Key securekey = getSecretKey(key);
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);
        byte[] bt = cipher.doFinal(data.getBytes());
        String strs = new BASE64Encoder().encode(bt);
        return strs;
    }


    public static String detrypt(String message, String key) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        sr.setSeed(key.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        Key securekey = getSecretKey(key);
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
        byte[] res = new BASE64Decoder().decodeBuffer(message);
        res = cipher.doFinal(res);
        return new String(res);
    }

    public static void main(String[] args) throws Exception {
        String message = "123qwe..";
        String key = "zhuxianfei";
        String entryptedMsg = encrypt(message, key);
        log.info("加密信息如下：" + entryptedMsg);
        String decryptedMsg = detrypt(entryptedMsg, key);
        log.info("解密信息如下：" + decryptedMsg);
    }
}
