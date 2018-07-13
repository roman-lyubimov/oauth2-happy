import { Config } from './config';
import { Token } from './token';
import { Fetch } from './fetch';
export declare class Client {
    readonly config: Config;
    private fetch;
    private token?;
    private tokenPromise?;
    constructor(config: Config, _fetch?: Fetch);
    getToken(): Promise<Token | null>;
    passwordCredentialsToken(username: string, password: string): Promise<Token>;
    retrieveToken(v: {
        [key: string]: string;
    }): Promise<Token>;
}
