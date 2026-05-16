export {
  getRuntime,
  deriveSessionKey,
  type RuntimeState,
} from "./initializer.js";
// _resetRuntime is intentionally NOT exported here — test-only helper.
// Import directly in tests: import { _resetRuntime } from '@torii-gate/core/runtime/initializer.js'
