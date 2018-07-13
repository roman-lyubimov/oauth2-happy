'use strict';

const expect = require('chai').expect;
const sinon = require('sinon');
const Token = require('../dist').Token;

describe('Token', () => {
  describe('#type', () => {
    it('should return "Bearer" by default', () => {
      const token = new Token('atok', 'unknown', 'rtok', 3600);
      expect(token.type).to.be.equal('Bearer');
    });

    it('should return "Bearer" if token is bearer', () => {
      const token = new Token('atok', 'bearer', 'rtok', 3600);
      expect(token.type).to.be.equal('Bearer');
    });
  });

  describe('#isExpired', () => {
    it('should return true if token is expired', () => {
      const token = new Token('atok', 'bearer', 'rtok', 0);
      expect(token.isExpired).to.be.true;
    });

    it('should return true if token is not expired', () => {
      const token = new Token('atok', 'bearer', 'rtok', 3600);
      expect(token.isExpired).to.be.false;
    });
  });

  describe('#isValid', () => {
    it('should return false if accessToken is missing', () => {
      const token = new Token(undefined, 'bearer', 'rtok', 3600);
      expect(token.isValid).to.be.false;
    });

    it('should return false if accessToken is empty string', () => {
      const token = new Token('', 'bearer', 'rtok', 3600);
      expect(token.isValid).to.be.false;
    });

    it('should return false if token is expired', () => {
      const token = new Token('atok', 'bearer', 'rtok', 0);
      expect(token.isValid).to.be.false;
    });

    it('should return true if ok', () => {
      const token = new Token('atok', 'bearer', 'rtok', 3600);
      expect(token.isValid).to.be.true;
    });
  });

  describe('#setAuthHeader', () => {
    it('should authorize a code block', () => {
      const token = new Token('atok', 'bearer', 'rtok', 3600);
      const blockFake = sinon.fake();
      token.setAuthHeader(blockFake);
      expect(blockFake.calledOnceWith('Authorization', 'Bearer atok')).to.be.true;
    });
  });
});