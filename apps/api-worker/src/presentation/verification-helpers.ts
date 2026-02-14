import {
  decodeJwkPublicKeyMultibase,
  verifyCredentialProofWithDataIntegrity,
  verifyCredentialProofWithEd25519Signature2020,
  type Ed25519PublicJwk,
  type JsonObject,
} from '@credtrail/core-domain';

interface CredentialProofVerificationSummary {
  status: 'valid' | 'invalid' | 'unchecked';
  format: string | null;
  cryptosuite: string | null;
  verificationMethod: string | null;
  reason: string | null;
}

interface CredentialLifecycleVerificationSummary {
  state: 'active' | 'expired' | 'revoked';
  reason: string | null;
  checkedAt: string;
  expiresAt: string | null;
  revokedAt: string | null;
}

interface CredentialStatusListReference extends JsonObject {
  id: string;
  type: string;
  statusPurpose: 'revocation';
  statusListIndex: string;
  statusListCredential: string;
}

interface CredentialVerificationCheckSummary {
  status: 'valid' | 'invalid' | 'unchecked';
  reason: string | null;
}

interface CredentialDateVerificationCheckSummary extends CredentialVerificationCheckSummary {
  validFrom: string | null;
  validUntil: string | null;
}

interface CredentialStatusVerificationCheckSummary extends CredentialVerificationCheckSummary {
  type: string | null;
  statusPurpose: string | null;
  statusListIndex: string | null;
  statusListCredential: string | null;
  revoked: boolean | null;
}

interface CredentialVerificationChecksSummary {
  jsonLdSafeMode: CredentialVerificationCheckSummary;
  credentialSchema: CredentialVerificationCheckSummary;
  credentialSubject: CredentialVerificationCheckSummary;
  dates: CredentialDateVerificationCheckSummary;
  credentialStatus: CredentialStatusVerificationCheckSummary;
}

export interface PresentationCredentialBindingSummary {
  status: 'valid' | 'invalid';
  reason: string | null;
}

export interface PresentationCredentialVerificationResult {
  credentialId: string | null;
  subjectId: string | null;
  binding: PresentationCredentialBindingSummary;
  proof: CredentialProofVerificationSummary;
  checks: CredentialVerificationChecksSummary;
  lifecycle: CredentialLifecycleVerificationSummary;
  status: 'valid' | 'invalid';
}

interface CreatePresentationVerificationHelpersInput<ContextType> {
  asJsonObject: (value: unknown) => JsonObject | null;
  asNonEmptyString: (value: unknown) => string | null;
  asString: (value: unknown) => string | null;
  selectCredentialProofObject: (credential: JsonObject) => JsonObject | null;
  verifyCredentialProofSummary: (
    context: ContextType,
    credential: JsonObject,
  ) => Promise<CredentialProofVerificationSummary>;
  summarizeCredentialVerificationChecks: (input: {
    context: ContextType;
    credential: JsonObject;
    checkedAt: string;
    expectedStatusList: CredentialStatusListReference | null;
  }) => Promise<CredentialVerificationChecksSummary>;
  summarizeCredentialLifecycleVerification: (
    credential: JsonObject,
    revokedAt: string | null,
    checkedAt: string,
  ) => CredentialLifecycleVerificationSummary;
}

const didKeyMultibaseFromDid = (did: string): string | null => {
  if (!did.startsWith('did:key:')) {
    return null;
  }

  const multibase = did.slice('did:key:'.length).trim();
  return multibase.length === 0 ? null : multibase;
};

export const didKeyVerificationMethod = (did: string): string | null => {
  const multibase = didKeyMultibaseFromDid(did);
  return multibase === null ? null : did + '#' + multibase;
};

export const ed25519PublicJwkFromDidKey = (did: string): Ed25519PublicJwk | null => {
  const multibase = didKeyMultibaseFromDid(did);

  if (multibase === null) {
    return null;
  }

  try {
    return {
      kty: 'OKP',
      crv: 'Ed25519',
      x: decodeJwkPublicKeyMultibase(multibase),
    };
  } catch {
    return null;
  }
};

export const verifiableCredentialObjectsFromPresentation = (
  presentation: JsonObject,
  asJsonObject: (value: unknown) => JsonObject | null,
): JsonObject[] | null => {
  const verifiableCredentialValue = presentation.verifiableCredential;

  if (!Array.isArray(verifiableCredentialValue)) {
    return null;
  }

  const credentials: JsonObject[] = [];

  for (const entry of verifiableCredentialValue) {
    const credential = asJsonObject(entry);

    if (credential === null) {
      return null;
    }

    credentials.push(credential);
  }

  return credentials;
};

const statusListReferenceFromCredentialForPresentation = (
  credential: JsonObject,
  asJsonObject: (value: unknown) => JsonObject | null,
  asNonEmptyString: (value: unknown) => string | null,
): CredentialStatusListReference | null => {
  const credentialStatus = asJsonObject(credential.credentialStatus);

  if (credentialStatus === null) {
    return null;
  }

  const type = asNonEmptyString(credentialStatus.type);
  const statusPurpose = asNonEmptyString(credentialStatus.statusPurpose) ?? 'revocation';
  const statusListIndex = asNonEmptyString(credentialStatus.statusListIndex);
  const statusListCredential = asNonEmptyString(credentialStatus.statusListCredential);

  if (
    type === null ||
    statusListIndex === null ||
    statusListCredential === null ||
    statusPurpose !== 'revocation'
  ) {
    return null;
  }

  return {
    id: statusListCredential + '#' + statusListIndex,
    type,
    statusPurpose: 'revocation',
    statusListIndex,
    statusListCredential,
  };
};

const credentialChecksPassPresentationPolicy = (
  checks: CredentialVerificationChecksSummary,
): boolean => {
  return (
    checks.jsonLdSafeMode.status === 'valid' &&
    checks.credentialSchema.status !== 'invalid' &&
    checks.credentialSubject.status === 'valid' &&
    checks.dates.status === 'valid' &&
    checks.credentialStatus.status !== 'invalid'
  );
};

interface PresentationVerificationHelpers<ContextType> {
  verifyPresentationHolderProofSummary: (
    context: ContextType,
    presentation: JsonObject,
    holderDid: string,
  ) => Promise<CredentialProofVerificationSummary>;
  verifyCredentialInPresentation: (request: {
    context: ContextType;
    credential: JsonObject;
    holderDid: string;
    checkedAt: string;
  }) => Promise<PresentationCredentialVerificationResult>;
}

export const createPresentationVerificationHelpers = <ContextType>(
  input: CreatePresentationVerificationHelpersInput<ContextType>,
): PresentationVerificationHelpers<ContextType> => {
  const verifyDidKeyHolderProofSummary = async (
    presentation: JsonObject,
    holderDid: string,
  ): Promise<CredentialProofVerificationSummary> => {
    const proof = input.selectCredentialProofObject(presentation);

    if (proof === null) {
      return {
        status: 'unchecked',
        format: null,
        cryptosuite: null,
        verificationMethod: null,
        reason: 'presentation has no proof object',
      };
    }

    const proofType = input.asNonEmptyString(proof.type);
    const proofValue = input.asNonEmptyString(proof.proofValue);
    const proofPurpose = input.asNonEmptyString(proof.proofPurpose);
    const verificationMethod = input.asNonEmptyString(proof.verificationMethod);
    const expectedVerificationMethod = didKeyVerificationMethod(holderDid);

    if (
      proofType === null ||
      proofValue === null ||
      proofPurpose === null ||
      verificationMethod === null
    ) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: input.asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'proof object is missing required fields',
      };
    }

    if (expectedVerificationMethod === null || verificationMethod !== expectedVerificationMethod) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: input.asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'verificationMethod must match the did:key holder DID',
      };
    }

    if (proofPurpose !== 'assertionMethod') {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: input.asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'proofPurpose must be assertionMethod',
      };
    }

    const holderPublicJwk = ed25519PublicJwkFromDidKey(holderDid);

    if (holderPublicJwk === null) {
      return {
        status: 'invalid',
        format: proofType,
        cryptosuite: input.asNonEmptyString(proof.cryptosuite),
        verificationMethod,
        reason: 'holder DID did:key value is not a valid Ed25519 multibase key',
      };
    }

    if (proofType === 'Ed25519Signature2020') {
      const isValid = await verifyCredentialProofWithEd25519Signature2020({
        credential: {
          ...presentation,
          proof: {
            type: 'Ed25519Signature2020',
            created: input.asString(proof.created) ?? '',
            proofPurpose: 'assertionMethod',
            verificationMethod,
            proofValue,
          },
        },
        publicJwk: holderPublicJwk,
      });

      return {
        status: isValid ? 'valid' : 'invalid',
        format: proofType,
        cryptosuite: null,
        verificationMethod,
        reason: isValid ? null : 'signature verification failed',
      };
    }

    if (proofType === 'DataIntegrityProof') {
      const cryptosuite = input.asNonEmptyString(proof.cryptosuite);

      if (cryptosuite !== 'eddsa-rdfc-2022') {
        return {
          status: 'invalid',
          format: proofType,
          cryptosuite,
          verificationMethod,
          reason: 'did:key holder proofs only support DataIntegrity cryptosuite eddsa-rdfc-2022',
        };
      }

      const isValid = await verifyCredentialProofWithDataIntegrity({
        credential: {
          ...presentation,
          proof: {
            type: 'DataIntegrityProof',
            cryptosuite,
            created: input.asString(proof.created) ?? '',
            proofPurpose: 'assertionMethod',
            verificationMethod,
            proofValue,
          },
        },
        publicJwk: holderPublicJwk,
      });

      return {
        status: isValid ? 'valid' : 'invalid',
        format: proofType,
        cryptosuite,
        verificationMethod,
        reason: isValid ? null : 'signature verification failed',
      };
    }

    return {
      status: 'unchecked',
      format: proofType,
      cryptosuite: input.asNonEmptyString(proof.cryptosuite),
      verificationMethod,
      reason: 'proof format is not currently supported',
    };
  };

  const verifyPresentationHolderProofSummary = async (
    context: ContextType,
    presentation: JsonObject,
    holderDid: string,
  ): Promise<CredentialProofVerificationSummary> => {
    if (holderDid.startsWith('did:key:')) {
      return verifyDidKeyHolderProofSummary(presentation, holderDid);
    }

    return input.verifyCredentialProofSummary(context, {
      ...presentation,
      issuer: holderDid,
    });
  };

  const verifyCredentialInPresentation = async (request: {
    context: ContextType;
    credential: JsonObject;
    holderDid: string;
    checkedAt: string;
  }): Promise<PresentationCredentialVerificationResult> => {
    const credentialId = input.asNonEmptyString(request.credential.id);
    const credentialSubject = input.asJsonObject(request.credential.credentialSubject);
    const subjectId = input.asNonEmptyString(credentialSubject?.id);
    const binding: PresentationCredentialBindingSummary =
      subjectId === null
        ? {
            status: 'invalid',
            reason: 'credentialSubject.id is missing',
          }
        : subjectId !== request.holderDid
          ? {
              status: 'invalid',
              reason: 'credentialSubject.id must match presentation holder DID',
            }
          : {
              status: 'valid',
              reason: null,
            };
    const checks = await input.summarizeCredentialVerificationChecks({
      context: request.context,
      credential: request.credential,
      checkedAt: request.checkedAt,
      expectedStatusList: statusListReferenceFromCredentialForPresentation(
        request.credential,
        input.asJsonObject,
        input.asNonEmptyString,
      ),
    });
    const resolvedRevokedAt =
      checks.credentialStatus.status === 'valid'
        ? checks.credentialStatus.revoked
          ? request.checkedAt
          : null
        : null;
    const lifecycle = input.summarizeCredentialLifecycleVerification(
      request.credential,
      resolvedRevokedAt,
      request.checkedAt,
    );
    const proof = await input.verifyCredentialProofSummary(request.context, request.credential);
    const status: 'valid' | 'invalid' =
      binding.status === 'valid' &&
      proof.status === 'valid' &&
      credentialChecksPassPresentationPolicy(checks) &&
      lifecycle.state === 'active'
        ? 'valid'
        : 'invalid';

    return {
      credentialId,
      subjectId,
      binding,
      proof,
      checks,
      lifecycle,
      status,
    };
  };

  return {
    verifyPresentationHolderProofSummary,
    verifyCredentialInPresentation,
  };
};
