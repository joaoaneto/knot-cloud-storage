import Joi from 'joi';
import httpSignature from 'http-signature';
import fs from 'fs';
import sshpk from 'sshpk'

const messageSchema = Joi.object().keys({
  data: Joi.object().keys({
    devices: Joi.array(),
    topic: Joi.string().required(),
    payload: Joi.object().required(),
  }),
  metadata: Joi.object().keys({
    route: Joi.array().required(),
    date: Joi.date().required(),
  }),
});

function mapRequestToMessage(request) {
  return {
    data: request.payload,
    metadata: {
      route: JSON.parse(request.headers['x-meshblu-route']),
      date: new Date(request.headers.date),
    },
  };
}

function validateMessage(message) {
  const { error } = Joi.validate(message, messageSchema);
  if (error) {
    throw error;
  }
}

function verifySignature(request, publicKey) {
  const parsedReq = httpSignature.parseRequest(request, { clockSkew: Number.MAX_VALUE });
  console.log('SignedRequest: ', parsedReq);
  // const pkey = Buffer.from(publicKey, 'base64');
  console.log('Public Key: ', publicKey);

  // if (!httpSignature.verify(parsedReq, publicKey)) {
  //   throw new Error('Signature failed');
  // }

  const pubKey = sshpk.parseKey(publicKey);
  const v = pubKey.createVerify('rsa-sha256');
  console.log(parsedReq.algorithm);
  console.log(parsedReq.params.signature);
  console.log(parsedReq.signingString.length);
  console.log(Buffer.byteLength(parsedReq.signingString, 'utf8'))
  v.update(parsedReq.signingString);
  console.log(v.verify(parsedReq.params.signature, 'base64'));
}

class DataController {
  constructor(settings, saveDataInteractor, listDataInteractor, logger) {
    this.publicKey = Buffer.from(settings.server.publicKey, 'base64');
    this.saveDataInteractor = saveDataInteractor;
    this.listDataInteractor = listDataInteractor;
    this.logger = logger;
  }

  async save(request, h) {
    try {
      // this.publicKey = fs.readFileSync('publicKey.pem');
      // this.publicKey = `LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FR
      // OEFNSUlCQ2dLQ0FRRUFyUUdxVmhDVU5sakg0S2V4eUpObwpBazVFSXcyS0JZUW5rSkphYVhUVml0
      // cXNud1p5bGM0eUJKWlovS3J2UHhXdGlNYXFuRmV4eEVTck16SGVtaGZwCnBSTjdXR3hETmQxcnNB
      // cXpKbnJNNFowL3VWZ2ZYZUpsb3FxS2FWRkg4ZUtPcUJWS3dFK2ZxVzB4Z1oyTzRuK2QKT0JQM0wv
      // Y3oyaGRTQU1RaFEwU01hOU9RbWdXR3F1ejRQaDRjelkvb1lKUGcvWDJMSVQ1RGR6djBiVmJNNzll
      // awpDVk5JZkx2NnpBbVFPNTBUbkZyc3ZCeTZiZDM3azNUWWxjMGh4NzBDYnAwQjBabzFUQTlIbVp5
      // cHhkdVZ3VTNnCkt1TXZSMkhEUGdlTnY4QXAyYlA5L3lwZzk5c1NDYXV3NmM5SjQ3dHNDWWZQZC91
      // ZEUwcGV5bkxVU1R6cEQzRzcKUlFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==`;
      // this.publicKey = `-----BEGIN PUBLIC KEY-----
      // MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArQGqVhCUNljH4KexyJNo
      // Ak5EIw2KBYQnkJJaaXTVitqsnwZylc4yBJZZ/KrvPxWtiMaqnFexxESrMzHemhfp
      // pRN7WGxDNd1rsAqzJnrM4Z0/uVgfXeJloqqKaVFH8eKOqBVKwE+fqW0xgZ2O4n+d
      // OBP3L/cz2hdSAMQhQ0SMa9OQmgWGquz4Ph4czY/oYJPg/X2LIT5Ddzv0bVbM79ek
      // CVNIfLv6zAmQO50TnFrsvBy6bd37k3TYlc0hx70Cbp0B0Zo1TA9HmZypxduVwU3g
      // KuMvR2HDPgeNv8Ap2bP9/ypg99sSCauw6c9J47tsCYfPd/udE0peynLUSTzpD3G7
      // RQIDAQAB
      // -----END PUBLIC KEY-----`;
      verifySignature(request, this.publicKey);
      const message = mapRequestToMessage(request);
      validateMessage(message);
      await this.saveDataInteractor.execute(message);
      this.logger.info('Data saved');
      return h.response().code(201);
    } catch (err) {
      this.logger.error(`Failed saving data: ${err.message}`);
      return h.response().code(400);
    }
  }

  async list(request, h) {
    const credentials = {
      uuid: request.headers.auth_id,
      token: request.headers.auth_token,
    };

    try {
      const data = await this.listDataInteractor.execute(credentials, request.query);
      this.logger.info('Data obtained');
      return h.response(data).code(200);
    } catch (error) {
      this.logger.error(`Failed to list data (${error.code || 500}): ${error.message}`);
      return h.response(error.message).code(error.code);
    }
  }

  async listByDevice(request, h) {
    const credentials = {
      uuid: request.headers.auth_id,
      token: request.headers.auth_token,
    };
    const dataQuery = request.query;
    dataQuery.from = request.params.id;

    try {
      const data = await this.listDataInteractor.execute(credentials, dataQuery);
      this.logger.info('Data obtained');
      return h.response(data).code(200);
    } catch (error) {
      this.logger.error(`Failed to list data (${error.code || 500}): ${error.message}`);
      return h.response(error.message).code(error.code);
    }
  }

  async listBySensor(request, h) {
    const credentials = {
      uuid: request.headers.auth_id,
      token: request.headers.auth_token,
    };
    const dataQuery = request.query;
    dataQuery.from = request.params.deviceId;
    dataQuery.sensorId = request.params.sensorId;

    try {
      const data = await this.listDataInteractor.execute(credentials, dataQuery);
      this.logger.info('Data obtained');
      return h.response(data).code(200);
    } catch (error) {
      this.logger.error(`Failed to list data (${error.code || 500}): ${error.message}`);
      return h.response(error.message).code(error.code);
    }
  }
}

export default DataController;
