const jwt = require('jsonwebtoken');
const crypto = require('crypto');


const jwtSecret = 'myjwtsecret';
const encryptionKey = crypto.randomBytes(32); 
const iv = crypto.randomBytes(16);

const encrypt = (payload) => {
  const data = JSON.stringify(payload);

  const cipher = crypto.createCipheriv('aes-256-cbc', encryptionKey, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const token = jwt.sign({ data: encrypted, iv: iv.toString('hex') }, jwtSecret, { expiresIn: '1h' });

  return token;
};


const decrypt = (token) => {
  try {
    const decoded = jwt.verify(token, jwtSecret);

    const encryptedData = decoded.data;
    const ivFromToken = Buffer.from(decoded.iv, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKey, ivFromToken);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return JSON.parse(decrypted);
  } catch (error) {
    console.error('Decryption failed:', error.message);
    return null;
  }
};

module.exports = {
  encrypt,
  decrypt
};
