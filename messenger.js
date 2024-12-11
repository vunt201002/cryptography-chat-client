'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    // Generate ElGamal key pair
    this.EGKeyPair = await generateEG()

    // Return certificate with serialized public key
    return {
      username,
      publicKey: await cryptoKeyToJSON(this.EGKeyPair.pub)
    }
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
    // Verify the certificate using CA's public key
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature);
    if (!isValid) {
      throw new Error('Invalid certificate signature!')
    }

    // Store the certificate
    this.certs[certificate.username] = {
      username: certificate.username,
      publicKey: certificate.publicKey
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage (name, plaintext) {
    // Fetch recipient's certificate
    const receiverCert = this.certs[name]
    if (!receiverCert) throw new Error(`Certificate for ${name} not found`)

    // First message setup: Compute DH shared secret and initialize keys
    if (!this.conns[name]) {
      const sharedSecret = await computeDH(this.EGKeyPair.sec, receiverCert.publicKey)
      const rootKey = await HMACtoAESKey(sharedSecret, 'init')
      this.conns[name] = { sendingKey: rootKey }
    }

    const conn = this.conns[name]

    // Generate a random IV and derive the message key
    const iv = genRandomSalt()
    const messageKey = await HMACtoAESKey(conn.sendingKey, 'message-key')

    // Encrypt the message
    const ciphertext = await encryptWithGCM(messageKey, plaintext, iv, '')

    // Ratchet the sending key
    conn.sendingKey = await HMACtoHMACKey(conn.sendingKey, 'ratchet')

    // Encrypt the sending key for the government
    const govSharedKey = await computeDH(this.EGKeyPair.sec, this.govPublicKey)
    const govAESKey = await HMACtoAESKey(govSharedKey, govEncryptionDataStr)
    const ivGov = genRandomSalt()
    const encryptedKeyForGov = await encryptWithGCM(govAESKey, await cryptoKeyToJSON(conn.sendingKey), ivGov, '')

    // Build the message header
    const header = {
      ivGov,
      cGov: encryptedKeyForGov,
      receiverIV: iv
    }

    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    // Fetch sender's certificate
    const senderCert = this.certs[name]
    if (!senderCert) throw new Error(`Certificate for ${name} not found`)

    // First message setup: Compute DH shared secret and initialize keys
    if (!this.conns[name]) {
      const sharedSecret = await computeDH(this.EGKeyPair.sec, senderCert.publicKey)
      const rootKey = await HMACtoAESKey(sharedSecret, 'init')
      this.conns[name] = { receivingKey: rootKey }
    }

    const conn = this.conns[name]

    // Derive the message key and decrypt the message
    const messageKey = await HMACtoAESKey(conn.receivingKey, 'message-key')
    const plaintextBuffer = await decryptWithGCM(messageKey, ciphertext, header.receiverIV, '')

    // Ratchet the receiving key
    conn.receivingKey = await HMACtoHMACKey(conn.receivingKey, 'ratchet')

    return bufferToString(plaintextBuffer)
  }
};

module.exports = {
  MessengerClient
}
