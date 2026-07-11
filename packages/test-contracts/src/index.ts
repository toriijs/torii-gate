/**
 * @torii-gate/test-contracts
 *
 * RFC 9700 compliance testing framework for Token Handler session adapters.
 * Enables community adapter authors to validate OAuth 2.0 security requirements.
 *
 * Usage in adapter packages:
 *   import { runAdapterContractTests, VALID_SESSION } from '@torii-gate/test-contracts'
 */

export { runAdapterContractTests, runPendingStoreContractTests, mockRequest, extractCookieValue } from './contract.js';

export { runSecurityAuditTests } from './security-audit.js';

export {
  VALID_SESSION,
  MINIMAL_SESSION,
  EXPIRED_SESSION,
  SESSION_WITH_USERINFO,
  VALID_PENDING_AUTH,
  SHORT_TTL_PENDING_AUTH,
  EXPIRED_PENDING_AUTH,
} from './fixtures.js';

export type { AdapterType, PendingStoreType, AdapterContractOptions, PendingStoreContractOptions, SecurityAuditOptions } from './types.js';
