export interface Config {
    clientId: string;
    clientSecret?: string;
    endpoint: {
        tokenUrl: string;
    };
    scopes?: string[];
}
