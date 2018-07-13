export class Token {
  readonly expiryDelta = 10 * 1000; // 10s
  readonly expiresAt: number;

  constructor(
    readonly accessToken: string,
    readonly tokenType: string,
    readonly refreshToken: string,
    readonly expiresIn: number
  ) {
    this.expiresAt = Date.now() + expiresIn * 1000;
  }

  get type(): string {
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

  setAuthHeader(block: (header: string, value: string) => void) {
    block('Authorization', this.type + ' ' + this.accessToken);
  }
}
