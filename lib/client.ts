import {Config} from './config';
import {Token} from './token';
import {Fetch} from './fetch';

export class Client {
  private fetch: Fetch;
  private token?: Token;
  private tokenPromise?: Promise<Token>;

  constructor(readonly config: Config, _fetch?: Fetch) {
    this.fetch = _fetch || fetch;
  }

  getToken(): Promise<Token|null> {
    if (this.token) {
      if (this.token.isValid) {
        return Promise.resolve(this.token);
      }

      if (!Boolean(this.token.refreshToken)) {
        return Promise.reject(new Error('Token expired and refresh token is not set'));
      }

      if (this.tokenPromise) {
        return this.tokenPromise;
      }

      return (this.tokenPromise = this.retrieveToken({
        grant_type: 'refresh_token',
        refresh_token: this.token.refreshToken
      }).then((token) => {
        this.tokenPromise = undefined;
        return (this.token = token);
      }));
    }
    return Promise.resolve(null);
  }

  passwordCredentialsToken(username: string, password: string): Promise<Token> {
    const v = <{ [key: string]: string }>{
      grant_type: 'password',
      username: username,
      password: password,
    };

    if (this.config.scopes && this.config.scopes.length) {
      v.scope = this.config.scopes.join(' ');
    }

    return this.retrieveToken(v);
  }

  retrieveToken(v: { [key: string]: string }): Promise<Token> {
    v.client_id = this.config.clientId;

    if (this.config.clientSecret) {
      v.client_secret = this.config.clientSecret;
    }

    return this.fetch(this.config.endpoint.tokenUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: Object.keys(v).map((key) => {
        return encodeURIComponent(key) + '=' + encodeURIComponent(v[key]);
      }).join('&')
    }).then((response: Response) => {
      if (!response.ok) {
        return response.text().then((text) => {
          let message;

          if (response.status === 400) {
            let json;

            try {
              json = JSON.parse(text);
            } catch (error) {
              // Do nothing since we catch only SyntaxError
            }

            if (json && json['error']) {
              message = 'Cannot fetch token: ' + json['error'];

              if (json['error_description']) {
                message += "; Description: " + json['error_description'];
              }
            } else {
              message = `Cannot fetch token: ${response.statusText}; Response: ${text}`;
            }
          } else {
            message = `Cannot fetch token: ${response.statusText}; Response: ${text}`;
          }

          throw new Error(message);
        });
      }

      const mediaType = response.headers.get('Content-Type');

      if (mediaType === 'application/x-www-form-urlencoded' || mediaType === 'text/plain') {
        return response.formData();
      }

      return response.json();
    }, (error) => {
      throw new Error('Cannot fetch token; ' + error);
    }).then((response) => {
      if (!Boolean(response['access_token'])) {
        throw new Error('Server response missing access_token')
      }

      const refreshToken = response['refresh_token'] || v.refresh_token;
      const expiresIn = parseInt(response['expires_in']);

      return new Token(response['access_token'], response['token_type'], refreshToken, expiresIn);
    }, (error) => {
      if (error instanceof SyntaxError) {
        throw new Error('Server response invalid payload');
      }
      throw error;
    });
  }
}
