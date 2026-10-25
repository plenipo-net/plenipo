/**
 * Experimental formats. They work and are tested, but they follow drafts that are still moving:
 * - Delegate SD-JWT links (draft-gco-oauth-delegate-sd-jwt-00, an individual draft);
 * - TS12 e-mandate roots (urn:eudi:sca:emandate:1, EUDI technical specification still in draft);
 * - mandates on behalf of a legal person (urn:plenipo:representation:1, a Plenipo-defined attestation
 *   pending a European representation attestation or the EUDI Business Wallet).
 * Their API may change in any minor release. Verifiers accept them only when configured to:
 * `delegationFormats: ['jws', 'sd-jwt']`, `emandate`, `representation` in `VerifyOptions`.
 */
// Delegate SD-JWT
export { delegateMandateSdJwt } from './mandate.js';
export {
  parseDelegation,
  createDelegateTransactionData,
  DELEGATE_SDJWT_TYP,
  DELEGATE_TX_DATA_TYPE,
  PLENIPO_MANDATE_CLAIM,
  MAX_DELEGATION_LENGTH,
  type DelegationFormat,
  type ParsedDelegation,
  type DelegateTransactionData,
  type DelegateTransactionDataInput,
} from './delegate-sdjwt.js';

// TS12 e-mandates and legal persons
export {
  checkAttestationCertificates,
  checkAttestationStatus,
  SCA_QUERY_ID,
  type DeferredCertificateCheck,
  type DeferredStatus,
  type EmandateVerifyOptions,
} from './root.js';
export {
  currencyMinorDigits,
  NON_DECIMAL_CURRENCY_EXPONENTS,
  decodeCanonical,
  describeMandate,
  emandateViolations,
  encodeEmandateTransactionData,
  mandateToEmandate,
  parseDateTime,
  toMajorUnits,
  toMinorUnits,
  type EmandateCheckOptions,
  type EmandateMappingOptions,
  type EmandatePayee,
  type EmandatePayload,
  type EmandatePaymentPayload,
  type EmandateTransactionData,
  type EmandateViolation,
} from './ts12.js';
export {
  checkRepresentation,
  createLegalMandate,
  legalPrincipalProblems,
  representationClaimsProblems,
  representationQuery,
  rolePowerViolations,
  RepresentationError,
  REPRESENTATION_QUERY_ID,
  type RepresentationClaims,
  type RepresentationVerifyOptions,
  type VerifiedRepresentation,
} from './legal.js';
export {
  verifyAttestationPresentation,
  disclosedProtectedClaims,
  PresentationError,
  PROTECTED_CLAIMS,
  type VerifiedPresentation,
} from './presentation.js';
