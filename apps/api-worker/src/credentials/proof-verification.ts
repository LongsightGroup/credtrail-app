import {
  verifyCredentialProofWithDataIntegrity,
  verifyCredentialProofWithEd25519Signature2020,
  type Ed25519PublicJwk,
  type JsonObject,
  type P256PublicJwk,
} from '@credtrail/core-domain';
import { type TenantSigningRegistryEntry } from '@credtrail/validation';
import { issuerIdentifierFromCredential } from '../badges/credential-display';
import {
  isEd25519SigningPublicJwk,
  isP256SigningPublicJwk,
  toEd25519PublicJwk,
  toP256PublicJwk,
  type SigningPublicJwk,
} from '../signing/key-material';
import type { HistoricalSigningKeyEntry } from '../signing/registry';
import { asJsonObject, asNonEmptyString, asString } from '../utils/value-parsers';

export interface CredentialProofVerificationSummary {
  status: 'valid' | 'invalid' | 'unchecked';
  format: string | null;
  cryptosuite: string | null;
  verificationMethod: string | null;
  reason: string | null;
}

interface CreateCredentialProofVerificationHelpersInput<ContextType> {
  resolveSigningEntryForDid: (
    context: ContextType,
    did: string,
  ) => Promise<TenantSigningRegistryEntry | null>;
  resolveHistoricalSigningKeysForDid: (
    context: ContextType,
    did: string,
  ) => readonly HistoricalSigningKeyEntry[];
}

export interface CredentialProofVerificationHelpers<ContextType> {
  selectCredentialProofObject: (credential: JsonObject) => JsonObject | null;
  verifyCredentialProofSummary: (
    context: ContextType,
    credential: JsonObject,
  ) => Promise<CredentialProofVerificationSummary>;
}

export const createCredentialProofVerificationHelpers = <ContextType>(
  input: CreateCredentialProofVerificationHelpersInput<ContextType>,
): CredentialProofVerificationHelpers<ContextType> => {
  const selectCredentialProofObject = (credential: JsonObject): JsonObject | null => {
    const credentialProofValue = credential.proof;
    const singleProof = asJsonObject(credentialProofValue);

    if (singleProof !== null) {
      return singleProof;
    }

    if (!Array.isArray(credentialProofValue)) {
      return null;
    }

    const proofEntries = credentialProofValue
      .map((entry) => asJsonObject(entry))
      .filter((entry) => entry !== null);
    const assertionMethodEntry = proofEntries.find((entry) => {
      return asNonEmptyString(entry.proofPurpose) === 'assertionMethod';
    });

    return assertionMethodEntry ?? proofEntries[0] ?? null;
  };

  const resolveVerificationPublicJwkForDidKeyId = (request: {
    context: ContextType;
    did: string;
    keyId: string;
    activeSigningEntry: TenantSigningRegistryEntry;
  }): SigningPublicJwk | null => {
    if (request.keyId === request.activeSigningEntry.keyId) {
      return request.activeSigningEntry.publicJwk;
    }

    const historicalEntry = input.resolveHistoricalSigningKeysForDid(request.context, request.did).find(
      (entry) => {
        return entry.keyId === request.keyId;
      },
    );

    return historicalEntry?.publicJwk ?? null;
  };

  const verifyCredentialProofWithPublicJwk = async (request: {
    credential: JsonObject;
    proof: JsonObject;
    proofType: string;
    proofValue: string;
    verificationMethod: string;
    publicJwk: SigningPublicJwk;
  }): Promise<CredentialProofVerificationSummary> => {
    if (request.proofType === 'Ed25519Signature2020') {
      if (!isEd25519SigningPublicJwk(request.publicJwk)) {
        return {
          status: 'invalid',
          format: request.proofType,
          cryptosuite: null,
          verificationMethod: request.verificationMethod,
          reason: 'Ed25519Signature2020 requires an Ed25519 public key',
        };
      }

      const isValid = await verifyCredentialProofWithEd25519Signature2020({
        credential: {
          ...request.credential,
          proof: {
            type: 'Ed25519Signature2020',
            created: asString(request.proof.created) ?? '',
            proofPurpose: 'assertionMethod',
            verificationMethod: request.verificationMethod,
            proofValue: request.proofValue,
          },
        },
        publicJwk: toEd25519PublicJwk(request.publicJwk),
      });

      return {
        status: isValid ? 'valid' : 'invalid',
        format: request.proofType,
        cryptosuite: null,
        verificationMethod: request.verificationMethod,
        reason: isValid ? null : 'signature verification failed',
      };
    }

    if (request.proofType === 'DataIntegrityProof') {
      const cryptosuite = asNonEmptyString(request.proof.cryptosuite);

      if (cryptosuite !== 'eddsa-rdfc-2022' && cryptosuite !== 'ecdsa-sd-2023') {
        return {
          status: 'invalid',
          format: request.proofType,
          cryptosuite,
          verificationMethod: request.verificationMethod,
          reason: 'unsupported Data Integrity cryptosuite',
        };
      }

      let verificationPublicJwk: Ed25519PublicJwk | P256PublicJwk;

      if (cryptosuite === 'eddsa-rdfc-2022') {
        if (!isEd25519SigningPublicJwk(request.publicJwk)) {
          return {
            status: 'invalid',
            format: request.proofType,
            cryptosuite,
            verificationMethod: request.verificationMethod,
            reason: 'eddsa-rdfc-2022 requires an Ed25519 public key',
          };
        }

        verificationPublicJwk = toEd25519PublicJwk(request.publicJwk);
      } else {
        if (!isP256SigningPublicJwk(request.publicJwk)) {
          return {
            status: 'invalid',
            format: request.proofType,
            cryptosuite,
            verificationMethod: request.verificationMethod,
            reason: 'ecdsa-sd-2023 requires a P-256 public key',
          };
        }

        verificationPublicJwk = toP256PublicJwk(request.publicJwk);
      }

      const isValid = await verifyCredentialProofWithDataIntegrity({
        credential: {
          ...request.credential,
          proof: {
            type: 'DataIntegrityProof',
            cryptosuite,
            created: asString(request.proof.created) ?? '',
            proofPurpose: 'assertionMethod',
            verificationMethod: request.verificationMethod,
            proofValue: request.proofValue,
          },
        },
        publicJwk: verificationPublicJwk,
      });

      return {
        status: isValid ? 'valid' : 'invalid',
        format: request.proofType,
        cryptosuite,
        verificationMethod: request.verificationMethod,
        reason: isValid ? null : 'signature verification failed',
      };
    }

    return {
      status: 'unchecked',
      format: request.proofType,
      cryptosuite: asNonEmptyString(request.proof.cryptosuite),
      verificationMethod: request.verificationMethod,
      reason: 'proof format is not currently supported',
    };
  };

  const verifyCredentialProofSummary = async (
    context: ContextType,
    credential: JsonObject,
  ): Promise<CredentialProofVerificationSummary> => {
    const proof = selectCredentialProofObject(credential);

    if (proof === null) {
      return {
        status: 'unchecked',
        format: null,
        cryptosuite: null,
        verificationMethod: null,
        reason: 'credential has no proof object',
      };
    }

    const proofType = asNonEmptyString(proof.type);
    const proofValue = asNonEmptyString(proof.proofValue);
    const proofPurpose = asNonEmptyString(proof.proofPurpose);
    const verificationMethod = asNonEmptyString(proof.verificationMethod);
    const verificationMethodParts =
      verificationMethod === null ? null : verificationMethod.split('#', 2);
    const verificationMethodKeyId =
      verificationMethodParts === null
        ? null
        : (() => {
            const [, keyId] = verificationMethodParts;
            return keyId === undefined || keyId.length === 0 ? null : keyId;
          })();
    const methodDid =
      verificationMethodParts === null
        ? null
        : (() => {
            const [didPart] = verificationMethodParts;
            return didPart === undefined || didPart.length === 0 ? null : didPart;
          })();
    const issuerIdentifier = issuerIdentifierFromCredential(credential);
    const issuerDidFromCredential = issuerIdentifier?.startsWith('did:') ? issuerIdentifier : null;
    const issuerDid = methodDid ?? issuerIdentifier;

    if (
      proofType === null ||
      proofValue === null ||
      proofPurpose === null ||
      verificationMethod === null
    ) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'proof object is missing required fields',
      };
    }

    if (proofPurpose !== 'assertionMethod') {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'proofPurpose must be assertionMethod',
      };
    }

    if (verificationMethodKeyId === null) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'verificationMethod must include a key fragment',
      };
    }

    if (
      methodDid !== null &&
      issuerDidFromCredential !== null &&
      methodDid !== issuerDidFromCredential
    ) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'verificationMethod DID must match credential issuer DID',
      };
    }

    if (!issuerDid?.startsWith('did:')) {
      return {
        status: 'unchecked',
        format: proofType,
        cryptosuite: asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'issuer DID could not be resolved for proof verification',
      };
    }

    const signingEntry = await input.resolveSigningEntryForDid(context, issuerDid);

    if (signingEntry === null) {
      return {
        status: 'unchecked',
        format: proofType,
        cryptosuite: asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: `no signing configuration for issuer DID ${issuerDid}`,
      };
    }

    if (verificationMethodKeyId !== signingEntry.keyId) {
      const historicalPublicJwk = resolveVerificationPublicJwkForDidKeyId({
        context,
        did: issuerDid,
        keyId: verificationMethodKeyId,
        activeSigningEntry: signingEntry,
      });

      if (historicalPublicJwk === null) {
        return {
          status: 'invalid',
          format: proofType,
          cryptosuite: asNonEmptyString(proof.cryptosuite),
          verificationMethod,
          reason:
            'verificationMethod key fragment must match an active or historical signing key id',
        };
      }

      return verifyCredentialProofWithPublicJwk({
        credential,
        proof,
        proofType,
        proofValue,
        verificationMethod,
        publicJwk: historicalPublicJwk,
      });
    }

    return verifyCredentialProofWithPublicJwk({
      credential,
      proof,
      proofType,
      proofValue,
      verificationMethod,
      publicJwk: signingEntry.publicJwk,
    });
  };

  return {
    selectCredentialProofObject,
    verifyCredentialProofSummary,
  };
};
