export declare class Token {
    readonly accessToken: string;
    readonly tokenType: string;
    readonly refreshToken: string;
    readonly expiresIn: number;
    readonly expiryDelta: number;
    readonly expiresAt: number;
    constructor(accessToken: string, tokenType: string, refreshToken: string, expiresIn: number);
    readonly type: string;
    readonly isExpired: boolean;
    readonly isValid: boolean;
    setAuthHeader(block: (header: string, value: string) => void): void;
}
