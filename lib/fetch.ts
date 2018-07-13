export interface Fetch {
  (input?: Request | string, init?: RequestInit): Promise<Response>;
}
