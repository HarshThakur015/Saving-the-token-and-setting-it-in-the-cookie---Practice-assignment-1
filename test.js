const { encrypt, decrypt } = require('./script');

const payload = { username: 'harshthakur', role: 'admin' };
const token = encrypt(payload);

console.log('Token:', token);

const decryptedPayload = decrypt(token);

if (decryptedPayload) {
  console.log('Decrypted Payload:', decryptedPayload);
  console.log('Success');
} else {
  console.log('Failed to decrypt.');
}
