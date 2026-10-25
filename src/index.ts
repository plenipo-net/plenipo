export * from './types.js';
export { createMandate, delegateMandate, encodeMandateTransactionData, nowSeconds, type MandateInput } from './mandate.js';
export { createInvocation, argsHash, type InvocationInput } from './invocation.js';
export { verifyAuthorization, peekInvocation, type VerifyOptions } from './verify.js';
export { verifyRoot, RootError, type RootResult } from './root.js';
export { generateAgentKey, type AgentKey } from './keys.js';
export {
  actionCovers,
  hostCovers,
  attenuationViolations,
  validateMandate,
  allowsDelegation,
  DEFAULT_MAX_LIFETIME,
  type PolicyOptions,
} from './scope.js';
export {
  InMemoryNonceStore,
  InMemoryRevocationRegistry,
  InMemorySpendingLedger,
  type NonceStore,
  type RevocationRegistry,
  type SpendingLedger,
} from './registry.js';
export { canonicalize, mandateHash, sha256 } from './encoding.js';
export { resolveSigningKey, verifyX5c, TrustError, type TrustConfig, type ResolvedKey } from './trust.js';
export {
  checkStatus,
  StatusUnavailableError,
  defaultStatusFetcher,
  StatusListCache,
  StatusListPublisher,
  STATUS_INVALID,
  STATUS_SUSPENDED,
  STATUS_VALID,
  type StatusFetcher,
  type StatusReference,
} from './status.js';
export {
  createMandateRequest,
  handleMandateResponse,
  authorizationRequestUrl,
  PID_QUERY_ID,
  type MandateRequest,
  type MandateRequestOptions,
  type MandateRequestSession,
  type MandateResponseOptions,
  type MandateResponseResult,
} from './openid4vp.js';
export { checkPidStatus, decodeMandateTransactionData, type RootOptions } from './root.js';
export { httpsOrigin, isStatusReference } from './status.js';

export type { DelegationFormat } from './delegate-sdjwt.js';

// stores
export * from './stores/index.js';

// service
export { urlFromRawTarget, pathProblem, TargetError } from './http/target.js';
export {
  DENY_PROBLEMS,
  GATEWAY_PROBLEMS,
  PROBLEM_TYPE_BASE,
  PROBLEM_CONTENT_TYPE,
  problemForDecision,
  problemSpecForDecision,
  problemFromSpec,
  problemResponse,
  isDenyCode,
  type ProblemDetails,
  type ProblemSpec,
  type ProblemKind,
  type GatewayProblemCode,
  type ProblemResponseOptions,
} from './http/errors.js';
export {
  CHAIN_HEADER,
  INVOCATION_HEADER,
  DEFAULT_MAX_CHAIN_HEADER_BYTES,
  DEFAULT_MAX_INVOCATION_HEADER_BYTES,
  authorizationHeaders,
  encodeChainHeader,
  parseAuthorizationHeaders,
  asMandateChain,
  type HeaderLimits,
  type ParsedAuthorization,
} from './http/transport.js';
export {
  createGateway,
  defaultRequestArgs,
  jsonMediaType,
  hasDuplicateJsonKeys,
  outcomeFromHeader,
  OUTCOME_HEADER,
  DEFAULT_MAX_BODY_BYTES,
  type SettlementOutcome,
  type Gateway,
  type GatewayOptions,
  type GatewayRoute,
  type GatewayEvent,
  type GatewayRequestInfo,
  type RouteContext,
  type Downstream,
  type PolicyHook,
  type AuthorizeResult,
  type SettleInput,
  type AllowDecision,
  type DenyDecision,
} from './http/gateway.js';
export {
  toNodeListener,
  expressMiddleware,
  plenipoRoute,
  toFetchRequest,
  writeFetchResponse,
  type NodeAdapterOptions,
  type ExpressLikeRequest,
  type ExpressLikeNext,
  type ExpressLikeMiddleware,
  type PlenipoRequestContext,
} from './http/node.js';
export {
  createStatusService,
  ManagedStatusList,
  InMemoryStatusListStore,
  publisherSource,
  STATUS_LIST_CONTENT_TYPE,
  type StatusService,
  type StatusServiceOptions,
  type StatusListSource,
  type StatusListStore,
  type StatusListState,
  type StatusValue,
  type StatusOperation,
  type SetStatusResult,
  type AdminOperation,
  type AdminAuthorizer,
  type ManagedStatusListOptions,
} from './http/status-service.js';
export {
  AuditLog,
  InMemoryAuditStore,
  JsonlFileAuditStore,
  verifyAuditLog,
  auditRecordHash,
  sanitizeForAudit,
  AUDIT_GENESIS,
  AUDIT_RECORD_VERSION,
  AUDIT_SIGNATURE_TYP,
  type AuditRecord,
  type AuditEntry,
  type AuditEvent,
  type AuditStore,
  type AuditRedaction,
  type AuditSigner,
  type AuditLogOptions,
  type DecisionAuditInput,
  type AuditVerifyOptions,
  type AuditVerifyResult,
} from './audit.js';
export {
  toOpaInput,
  toCedarRequest,
  CEDAR_NAMESPACE,
  POLICY_INPUT_VERSION,
  DEFAULT_POLICY_PRINCIPAL_CLAIMS,
  type OpaInput,
  type CedarRequest,
  type CedarEntity,
  type CedarUid,
  type MandateLimitsView,
  type PolicyExportOptions,
} from './policy-export.js';
export {
  principalIdentity,
  isLegalPersonPrincipal,
  isLegalPersonDecision,
  PrincipalIdentityError,
  DEFAULT_PRINCIPAL_ID_CLAIMS,
  type PrincipalIdentity,
  type PrincipalIdBasis,
  type PersonIdentity,
  type PrincipalIdentityOptions,
} from './principal.js';

export { MAX_PURPOSE_LENGTH } from './scope.js';

// signer
export {
  signCompactJwt,
  externalSignerFromDer,
  ecdsaDerToJose,
  isExternalSigner,
  type ExternalSigner,
  type SigningKey,
  type JwsAlg,
} from './signer.js';

// trust
export { resolveSigningKeyAsync, checkChainRevocation } from './trust.js';
export {
  checkCertificateRevocation,
  httpRevocationFetcher,
  buildOcspRequest,
  RevocationCache,
  RevocationError,
  type CertificateRevocationOptions,
  type HttpRevocationFetcherOptions,
  type RevocationFetcher,
  type RevocationPolicy,
  type RevocationReport,
} from './x509-revocation.js';
export {
  loadTrustedList,
  listedServices,
  trustConfigFromLists,
  fetchTrustedList,
  TrustListError,
  LOTE_TYPE,
  LOTE_SERVICE_TYPE,
  type FetchTrustedListOptions,
  type ListedService,
  type ListedServicesOptions,
  type LoadTrustedListOptions,
  type TrustConfigFromListsOptions,
  type TrustedList,
  type TrustedListEntity,
  type TrustedListService,
} from './trustlist.js';

// chain review
export { chainHash } from './invocation.js';
export { decodeStatusList, readStatus, DEFAULT_MAX_STATUS_LIST_BYTES, type DecodedStatusList } from './status.js';
export type { CachedStatusInfo } from './x509-revocation.js';
