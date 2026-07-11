export interface CookieAdapterOptions {
  /**
   * Secret used to derive the AES-GCM encryption key via HKDF.
   * Minimum 32 characters.
   *
   * **Warning: Changing this invalidates all existing sessions**
   */
  secret: string;

  /** Session TTL in seconds — defaults to `900` (15 minutes) */
  maxAge?: number | undefined;
}
