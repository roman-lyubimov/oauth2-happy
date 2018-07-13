"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class Token {
    constructor(accessToken, tokenType, refreshToken, expiresIn) {
        this.accessToken = accessToken;
        this.tokenType = tokenType;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
        this.expiryDelta = 10 * 1000; // 10s
        this.expiresAt = Date.now() + expiresIn * 1000;
    }
    get type() {
        if (this.tokenType === 'bearer') {
            return 'Bearer';
        }
        return 'Bearer';
    }
    get isExpired() {
        return (this.expiresAt - this.expiryDelta) < Date.now();
    }
    get isValid() {
        return Boolean(this.accessToken) && !this.isExpired;
    }
    setAuthHeader(block) {
        block('Authorization', this.type + ' ' + this.accessToken);
    }
}
exports.Token = Token;
