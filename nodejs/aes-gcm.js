var _crypto = require('crypto');
var _tag;

function main() {
    let content = "I need encrypt";
    let key = "2836e95fcd10e04b0069bb1ee659955b";

    let data = aesGcmEncrypt(content, key);
    console.log("加密后数据:" + data);
    console.log("解密后数据:" + aesGcmDecrypt(data, key));
}


/**
 * 
 * @param {*} message 
 * @param {*} key 
 */
function aesGcmEncrypt(message, key) {
    // AES 128 GCM Mode
    let iv = _crypto.randomBytes(12);
    const cipher = _crypto.createCipheriv('aes-128-gcm', Buffer.from(key, "hex"), iv);
    cipher.setAutoPadding(true);
    // encrypt the given text

    const encrypted = Buffer.concat([cipher.update(message, 'utf8'), cipher.final()]);
    console.log("length " + encrypted.length);

    // extract the auth tag
    const tag = cipher.getAuthTag();
    _tag = tag;
    console.log("tag    ", tag.length);
    // generate output
    return Buffer.concat([iv, encrypted, tag]).toString('base64');
}


/**
 * 
 * @param {*} message 
 * @param {*} key 
 */
function aesGcmDecrypt(message, key) {
    // AES 128 GCM Mode
    let data = Buffer.from(message, "base64");
    console.log("data length ", data.length);
    let iv = data.slice(0, 12);
    let body = data.slice(12, data.length - 16);
    console.log("body length " + body.length);
    let authTag = data.slice(data.length - 16);

    const decryptor = _crypto.createDecipheriv('aes-128-gcm', Buffer.from(key, "hex"), iv);
    decryptor.setAuthTag(authTag);
    // encrypt the given text


    let result = Buffer.concat([decryptor.update(body), decryptor.final()]);
    return result;
}


main();
