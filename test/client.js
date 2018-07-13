'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');
const {Client, Token} = require('../dist');

describe('Client', () => {
  describe('#getToken', () => {
    const successResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      json() {
        return Promise.resolve({
          access_token: 'accesstoken',
          token_type: 'bearer',
          expires_in: 3600,
          refresh_token: 'refreshtoken'
        })
      }
    };

    it('should resolves with null if there is no token', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      sinon.spy(client, 'retrieveToken');

      client.getToken().then((token) => {
        expect(client.retrieveToken.notCalled).to.be.true;
        expect(token).to.be.null;
        done();
      });
    });

    it('should reuse token', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.token = new Token('atok', 'bearer', 'rtok', 3600);

      client.getToken().then((token) => {
        expect(token).to.be.not.null;
        expect(token.accessToken).to.be.equal('atok');
        done();
      });
    });

    it('should throw an error if token expired and refreshToken is not set', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.token = new Token('atok', 'bearer', undefined, -1);

      client.getToken().catch((error) => {
        expect(error).to.be.instanceof(Error);
        expect(error.message).to.be.equal('Token expired and refresh token is not set');
        done();
      });
    });

    it('should refresh expired token', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      sinon.replace(client, 'retrieveToken', sinon.fake.resolves(new Token('atok2', 'bearer', 'rtok2', 3600)));

      client.token = new Token('atok', 'bearer', 'rtok', -1);

      client.getToken().then((token) => {
        expect(client.retrieveToken.calledOnceWith({grant_type: 'refresh_token', refresh_token: 'rtok'}));
        expect(token.accessToken).to.be.equal('atok2');
        done();
      });
    });

    it('should share a single #retrieveToken call until finished.', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      let resolve;

      // sinon.replace(client, 'retrieveToken', sinon.fake.resolves(new Token('atok2', 'bearer', 'rtok2', 3600)));
      sinon.replace(client, 'retrieveToken', sinon.fake.returns(new Promise((_resolve) => { resolve = _resolve})));

      client.token = new Token('atok', 'bearer', 'rtok', -1);

      Promise.all([
        client.getToken(),
        client.getToken(),
        client.getToken()
      ]).then((values) => {
        expect(values[0].accessToken).to.be.equal('atok2');
        expect(client.retrieveToken.calledOnceWith({grant_type: 'refresh_token', refresh_token: 'rtok'})).to.be.true;
        done();
      });

      resolve(new Token('atok2', 'bearer', 'rtok2', 3600));
    });

    it('should updated cached token', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      sinon.replace(client, 'retrieveToken', sinon.fake.resolves(new Token('atok2', 'bearer', 'rtok2', 3600)));

      client.token = new Token('atok', 'bearer', 'rtok', -1);

      client.getToken().then((token) => {
        expect(client.token.accessToken).to.be.equal('atok2');
        done();
      });
    });
  });

  describe('#passwordCredentialsToken', () => {
    const successResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      json() {
        return Promise.resolve({
          access_token: 'accesstoken',
          token_type: 'bearer',
          expires_in: 3600,
          refresh_token: 'refreshtoken'
        })
      }
    };

    it('should call #retrieveToken with correct grant', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      const username = 'admin';
      const password = 'adm1n';

      sinon.spy(client, 'retrieveToken');

      client.passwordCredentialsToken(username, password).then((token) => {
        expect(client.retrieveToken.calledOnceWith({grant_type: 'password', username, password}));
        done();
      });
    });

    it('should omit an empty scopes', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        },
        scopes: []
      }, fetch);

      sinon.spy(client, 'retrieveToken');

      client.passwordCredentialsToken('admin', 'adm1n').then((token) => {
        const spyCall = client.retrieveToken.getCall(0);
        const spyCallArgs = spyCall.args;
        expect('scope' in spyCallArgs[0]).to.be.false;
        done();
      });
    });

    it('should correctly encode requested scopes', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        },
        scopes: ['basic', 'email']
      }, fetch);

      sinon.spy(client, 'retrieveToken');

      client.passwordCredentialsToken('admin', 'adm1n').then((token) => {
        const spyCall = client.retrieveToken.getCall(0);
        const spyCallArgs = spyCall.args;
        expect(spyCallArgs[0].scope).to.be.equal('basic email');
        done();
      });
    });
  });

  describe('#retrieveToken', () => {
    const successResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      json() {
        return Promise.resolve({
          access_token: 'accesstoken',
          token_type: 'bearer',
          expires_in: 3600,
          refresh_token: 'refreshtoken'
        })
      }
    };

    const successExpiresIsStringResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      json() {
        return Promise.resolve({
          access_token: 'accesstoken',
          token_type: 'bearer',
          expires_in: '3600',
          refresh_token: 'refreshtoken'
        })
      }
    };

    const successInvalidPayloadResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      json() {
        throw new SyntaxError();
      }
    };

    const successMissingTokenResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      json() {
        return Promise.resolve({
          token_type: 'bearer',
          expires_in: 3600,
          refresh_token: 'refreshtoken'
        })
      }
    };

    const successWithoutRefreshTokenResponse = {
      ok: true,
      status: 200,
      statusText: 'OK',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      json() {
        return Promise.resolve({
          access_token: 'accesstoken',
          token_type: 'bearer',
          expires_in: 3600
        })
      }
    };

    const errorNormalResponse = {
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      text() {
        return Promise.resolve('{"error":"invalid_grant"}');
      }
    };

    const errorWithDescriptionResponse = {
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      text() {
        return Promise.resolve('{"error":"invalid_grant","error_description":"Ooops!"}');
      }
    };

    const errorInvalidCodeResponse = {
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      text() {
        return Promise.resolve('Internal server error');
      }
    };

    const errorInvalidPayloadResponse = {
      ok: false,
      status: 400,
      statusText: 'Bad Request',
      headers: {
        get(name) {
          return name === 'Content-Type' ? 'application/json' : null;
        }
      },
      text() {
        return Promise.resolve('{error=invalid_grant');
      }
    };

    it('should add a client id to the request body', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).then((token) => {
        expect(fetch.calledOnce).to.be.true;
        expect(fetch.calledWith('https://example.com/oauth2/token', sinon.match.has('body', 'client_id=12345'))).to.be.true;
        done();
      });
    });

    it('should add a client secret to the request body', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        clientSecret: '67890',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).then((token) => {
        expect(fetch.calledOnce).to.be.true;
        expect(fetch.calledWith('https://example.com/oauth2/token', sinon.match.has('body', 'client_id=12345&client_secret=67890'))).to.be.true;
        done();
      });
    });

    it('should send a properly formatted request', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        clientSecret: '67890',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({
        grant_type: 'password',
        username: 'admin',
        password: 'adm1n'
      }).then((token) => {
        expect(fetch.calledOnce).to.be.true;
        expect(fetch.calledWith('https://example.com/oauth2/token', sinon.match({
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        }))).to.be.true;
        done();
      });
    });

    it('should decode application/json response', (done) => {
      const fetch = sinon.fake.resolves(successResponse);

      const client = new Client({
        clientId: '12345',
        clientSecret: '67890',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({
        grant_type: 'password',
        username: 'admin',
        password: 'adm1n'
      }).then((token) => {
        expect(token).to.be.not.null;
        expect(token.accessToken).to.be.equal('accesstoken');
        expect(token.tokenType).to.be.equal('bearer');
        expect(token.expiresIn).to.be.equal(3600);
        expect(token.refreshToken).to.be.equal('refreshtoken');
        done();
      });
    });

    it('should reuse refresh token', (done) => {
      const fetch = sinon.fake.resolves(successWithoutRefreshTokenResponse);

      const client = new Client({
        clientId: '12345',
        clientSecret: '67890',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({
        grant_type: 'refresh_token',
        refresh_token: 'refreshtoken'
      }).then((token) => {
        expect(token).to.be.not.null;
        expect(token.accessToken).to.be.equal('accesstoken');
        expect(token.tokenType).to.be.equal('bearer');
        expect(token.expiresIn).to.be.equal(3600);
        expect(token.refreshToken).to.be.equal('refreshtoken');
        done();
      });
    });

    it('should throw an error if fetch fails', (done) => {
      const fetch = sinon.fake.rejects(new Error('Ooops!'));

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).catch((error) => {
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.be.equal('Cannot fetch token; Error: Ooops!');
        done();
      });
    });

    it('should throw an error if response code is 200 and invalid payload', (done) => {
      const fetch = sinon.fake.resolves(successInvalidPayloadResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).catch((error) => {
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.be.equal('Server response invalid payload');
        done();
      });
    });

    it('should throw an error if response code is 200 and missing token', (done) => {
      const fetch = sinon.fake.resolves(successMissingTokenResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).catch((error) => {
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.be.equal('Server response missing access_token');
        done();
      });
    });

    it('should throw an error if response code is 400 and normal error', (done) => {
      const fetch = sinon.fake.resolves(errorNormalResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).catch((error) => {
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.be.equal('Cannot fetch token: invalid_grant');
        done();
      });
    });

    it('should throw an error if response code is 400 and normal error with description', (done) => {
      const fetch = sinon.fake.resolves(errorWithDescriptionResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).catch((error) => {
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.be.equal('Cannot fetch token: invalid_grant; Description: Ooops!');
        done();
      });
    });

    it('should throw an error if unexpected response code', (done) => {
      const fetch = sinon.fake.resolves(errorInvalidCodeResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).catch((error) => {
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.be.equal('Cannot fetch token: Internal Server Error; Response: Internal server error');
        done();
      });
    });

    it('should throw an error if error invalid payload', (done) => {
      const fetch = sinon.fake.resolves(errorInvalidPayloadResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).catch((error) => {
        expect(error).to.be.an.instanceof(Error);
        expect(error.message).to.be.equal('Cannot fetch token: Bad Request; Response: {error=invalid_grant');
        done();
      });
    });

    it('should convert expires_in to number', (done) => {
      const fetch = sinon.fake.resolves(successExpiresIsStringResponse);

      const client = new Client({
        clientId: '12345',
        endpoint: {
          tokenUrl: 'https://example.com/oauth2/token'
        }
      }, fetch);

      client.retrieveToken({ }).then((token) => {
        expect(typeof token.expiresIn).to.be.equal('number');
        done();
      });
    });
  });
});