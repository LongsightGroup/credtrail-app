import type { JsonObject } from "./index";

const XSD_DATETIME = "http://www.w3.org/2001/XMLSchema#dateTime";
const XSD_BOOLEAN = "https://www.w3.org/2001/XMLSchema#boolean";
const XSD_ANY_URI = "https://www.w3.org/2001/XMLSchema#anyURI";
const VC_VOCAB = "https://www.w3.org/2018/credentials#";
const VC_STATUS_VOCAB = "https://www.w3.org/ns/credentials/status#";
const OB_VOCAB = "https://purl.imsglobal.org/spec/vc/ob/vocab.html#";
const SECURITY_VOCAB = "https://w3id.org/security#";

// Pinned context documents for offline JSON-LD canonicalization.
// Sources: W3C VC Data Model 2.0, W3C Bitstring Status List, 1EdTech OB3
// context-3.0.3, and CredTrail's TrustEd credential extension context.
const dataIntegrityProofContext = (): JsonObject => {
  return {
    "@protected": true,
    id: "@id",
    type: "@type",
    challenge: `${SECURITY_VOCAB}challenge`,
    created: {
      "@id": "http://purl.org/dc/terms/created",
      "@type": XSD_DATETIME,
    },
    cryptosuite: {
      "@id": `${SECURITY_VOCAB}cryptosuite`,
      "@type": `${SECURITY_VOCAB}cryptosuiteString`,
    },
    domain: `${SECURITY_VOCAB}domain`,
    expires: {
      "@id": `${SECURITY_VOCAB}expiration`,
      "@type": XSD_DATETIME,
    },
    nonce: `${SECURITY_VOCAB}nonce`,
    proofPurpose: {
      "@id": `${SECURITY_VOCAB}proofPurpose`,
      "@type": "@vocab",
      "@context": {
        "@protected": true,
        id: "@id",
        type: "@type",
        assertionMethod: {
          "@id": `${SECURITY_VOCAB}assertionMethod`,
          "@type": "@id",
          "@container": "@set",
        },
        authentication: {
          "@id": `${SECURITY_VOCAB}authenticationMethod`,
          "@type": "@id",
          "@container": "@set",
        },
      },
    },
    proofValue: {
      "@id": `${SECURITY_VOCAB}proofValue`,
      "@type": `${SECURITY_VOCAB}multibase`,
    },
    verificationMethod: {
      "@id": `${SECURITY_VOCAB}verificationMethod`,
      "@type": "@id",
    },
  };
};

export const pinnedJsonLdContexts: ReadonlyMap<string, JsonObject> = new Map<string, JsonObject>([
  [
    "https://www.w3.org/ns/credentials/v2",
    {
      "@context": {
        "@protected": true,
        id: "@id",
        type: "@type",
        "1EdTechJsonSchemaValidator2019": `${OB_VOCAB}1EdTechJsonSchemaValidator2019`,
        name: "https://schema.org/name",
        description: "https://schema.org/description",
        VerifiableCredential: {
          "@id": `${VC_VOCAB}VerifiableCredential`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            credentialStatus: {
              "@id": `${VC_VOCAB}credentialStatus`,
              "@type": "@id",
            },
            credentialSchema: {
              "@id": `${VC_VOCAB}credentialSchema`,
              "@type": "@id",
            },
            credentialSubject: {
              "@id": `${VC_VOCAB}credentialSubject`,
              "@type": "@id",
            },
            description: "https://schema.org/description",
            issuer: {
              "@id": `${VC_VOCAB}issuer`,
              "@type": "@id",
            },
            name: "https://schema.org/name",
            proof: {
              "@id": `${SECURITY_VOCAB}proof`,
              "@type": "@id",
              "@container": "@graph",
            },
            validFrom: {
              "@id": `${VC_VOCAB}validFrom`,
              "@type": XSD_DATETIME,
            },
            validUntil: {
              "@id": `${VC_VOCAB}validUntil`,
              "@type": XSD_DATETIME,
            },
          },
        },
        VerifiablePresentation: {
          "@id": `${VC_VOCAB}VerifiablePresentation`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            holder: {
              "@id": `${VC_VOCAB}holder`,
              "@type": "@id",
            },
            proof: {
              "@id": `${SECURITY_VOCAB}proof`,
              "@type": "@id",
              "@container": "@graph",
            },
            verifiableCredential: {
              "@id": `${VC_VOCAB}verifiableCredential`,
              "@type": "@id",
              "@container": "@graph",
              "@context": null,
            },
          },
        },
        DataIntegrityProof: {
          "@id": `${SECURITY_VOCAB}DataIntegrityProof`,
          "@context": dataIntegrityProofContext(),
        },
        BitstringStatusListCredential: `${VC_STATUS_VOCAB}BitstringStatusListCredential`,
        BitstringStatusList: {
          "@id": `${VC_STATUS_VOCAB}BitstringStatusList`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            encodedList: {
              "@id": `${VC_STATUS_VOCAB}encodedList`,
              "@type": `${SECURITY_VOCAB}multibase`,
            },
            statusPurpose: `${VC_STATUS_VOCAB}statusPurpose`,
          },
        },
        BitstringStatusListEntry: {
          "@id": `${VC_STATUS_VOCAB}BitstringStatusListEntry`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            statusListCredential: {
              "@id": `${VC_STATUS_VOCAB}statusListCredential`,
              "@type": "@id",
            },
            statusListIndex: `${VC_STATUS_VOCAB}statusListIndex`,
            statusPurpose: `${VC_STATUS_VOCAB}statusPurpose`,
          },
        },
      },
    },
  ],
  [
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json",
    {
      "@context": {
        "@protected": true,
        id: "@id",
        type: "@type",
        OpenBadgeCredential: `${OB_VOCAB}OpenBadgeCredential`,
        Profile: {
          "@id": `${OB_VOCAB}Profile`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            image: {
              "@id": `${OB_VOCAB}image`,
              "@type": "@id",
            },
            name: "https://schema.org/name",
            url: {
              "@id": "https://schema.org/url",
              "@type": XSD_ANY_URI,
            },
          },
        },
        AchievementSubject: {
          "@id": `${OB_VOCAB}AchievementSubject`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            achievement: `${OB_VOCAB}achievement`,
            evidence: {
              "@id": `${VC_VOCAB}evidence`,
              "@container": "@set",
            },
            identifier: {
              "@id": `${OB_VOCAB}identifier`,
              "@container": "@set",
            },
            result: {
              "@id": `${OB_VOCAB}result`,
              "@container": "@set",
            },
          },
        },
        Achievement: {
          "@id": `${OB_VOCAB}Achievement`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            achievementType: `${OB_VOCAB}achievementType`,
            alignment: {
              "@id": `${OB_VOCAB}alignment`,
              "@container": "@set",
            },
            criteria: {
              "@id": `${OB_VOCAB}Criteria`,
              "@type": "@id",
            },
            description: "https://schema.org/description",
            image: {
              "@id": `${OB_VOCAB}image`,
              "@type": "@id",
            },
            name: "https://schema.org/name",
          },
        },
        Alignment: {
          "@id": "https://schema.org/AlignmentObject",
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            frameworkUri: {
              "@id": "https://schema.org/targetUrl",
              "@type": XSD_ANY_URI,
            },
            targetFramework: "https://schema.org/targetFramework",
            targetName: "https://schema.org/targetName",
            targetUrl: {
              "@id": "https://schema.org/targetUrl",
              "@type": XSD_ANY_URI,
            },
          },
        },
        Criteria: {
          "@id": `${OB_VOCAB}Criteria`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            narrative: `${OB_VOCAB}narrative`,
          },
        },
        Evidence: {
          "@id": `${OB_VOCAB}Evidence`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            description: "https://schema.org/description",
            name: "https://schema.org/name",
          },
        },
        IdentityObject: {
          "@id": `${OB_VOCAB}IdentityObject`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            hashed: {
              "@id": `${OB_VOCAB}hashed`,
              "@type": XSD_BOOLEAN,
            },
            identityHash: `${OB_VOCAB}identityHash`,
            identityType: `${OB_VOCAB}identityType`,
          },
        },
        Image: {
          "@id": `${OB_VOCAB}Image`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            caption: "https://schema.org/caption",
          },
        },
        Result: {
          "@id": `${OB_VOCAB}Result`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            value: "https://schema.org/value",
          },
        },
        description: "https://schema.org/description",
        image: {
          "@id": `${OB_VOCAB}image`,
          "@type": "@id",
        },
        name: "https://schema.org/name",
        url: {
          "@id": "https://schema.org/url",
          "@type": XSD_ANY_URI,
        },
      },
    },
  ],
  [
    "https://www.w3.org/ns/credentials/status/v1",
    {
      "@context": {
        "@protected": true,
        id: "@id",
        type: "@type",
        BitstringStatusListCredential: `${VC_STATUS_VOCAB}BitstringStatusListCredential`,
        BitstringStatusList: {
          "@id": `${VC_STATUS_VOCAB}BitstringStatusList`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            encodedList: {
              "@id": `${VC_STATUS_VOCAB}encodedList`,
              "@type": `${SECURITY_VOCAB}multibase`,
            },
            statusPurpose: `${VC_STATUS_VOCAB}statusPurpose`,
          },
        },
        BitstringStatusListEntry: {
          "@id": `${VC_STATUS_VOCAB}BitstringStatusListEntry`,
          "@context": {
            "@protected": true,
            id: "@id",
            type: "@type",
            statusListCredential: {
              "@id": `${VC_STATUS_VOCAB}statusListCredential`,
              "@type": "@id",
            },
            statusListIndex: `${VC_STATUS_VOCAB}statusListIndex`,
            statusPurpose: `${VC_STATUS_VOCAB}statusPurpose`,
          },
        },
      },
    },
  ],
  [
    "https://credtrail.org/ns/trusted-credential/v1",
    {
      "@context": {
        "@protected": true,
        id: "@id",
        type: "@type",
        Assessment: `${OB_VOCAB}Assessment`,
        CreditValue: `${OB_VOCAB}CreditValue`,
        Duration: `${OB_VOCAB}Duration`,
        Endorsement: `${OB_VOCAB}Endorsement`,
        IssuerAuthority: `${OB_VOCAB}IssuerAuthority`,
        Rubric: `${OB_VOCAB}Rubric`,
        Skill: `${OB_VOCAB}Skill`,
        assessment: {
          "@id": `${OB_VOCAB}assessment`,
          "@container": "@set",
        },
        assessmentDate: `${OB_VOCAB}assessmentDate`,
        authorityType: `${OB_VOCAB}authorityType`,
        available: `${OB_VOCAB}available`,
        creditValue: `${OB_VOCAB}creditValue`,
        duration: `${OB_VOCAB}duration`,
        earned: `${OB_VOCAB}earned`,
        endorsement: {
          "@id": `${OB_VOCAB}endorsement`,
          "@container": "@set",
        },
        issuerAuthority: `${OB_VOCAB}issuerAuthority`,
        resultDate: {
          "@id": `${OB_VOCAB}resultDate`,
          "@type": XSD_DATETIME,
        },
        rubric: {
          "@id": `${OB_VOCAB}rubric`,
          "@container": "@set",
        },
        skill: {
          "@id": `${OB_VOCAB}skill`,
          "@container": "@set",
        },
        source: "https://schema.org/sourceOrganization",
        value: "https://schema.org/value",
      },
    },
  ],
]);

const asJsonObject = (value: unknown): JsonObject | null => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }

  return value as JsonObject;
};

const collectContextTerms = (value: unknown, terms: Set<string>): void => {
  if (Array.isArray(value)) {
    for (const entry of value) {
      collectContextTerms(entry, terms);
    }
    return;
  }

  const valueObject = asJsonObject(value);

  if (valueObject === null) {
    return;
  }

  const nestedContext = valueObject["@context"];

  if (nestedContext !== undefined && nestedContext !== value) {
    collectContextTerms(nestedContext, terms);
  }

  for (const [key, entryValue] of Object.entries(valueObject)) {
    if (key.startsWith("@")) {
      continue;
    }

    const normalizedKey = key.trim();

    if (normalizedKey.length > 0) {
      terms.add(normalizedKey);
    }

    const entryObject = asJsonObject(entryValue);

    if (entryObject?.["@context"] !== undefined) {
      collectContextTerms(entryObject["@context"], terms);
    }
  }
};

const contextTermsFromPinnedDocument = (document: JsonObject): readonly string[] => {
  const terms = new Set<string>();
  collectContextTerms(document["@context"], terms);
  return Array.from(terms).sort();
};

export const pinnedJsonLdContextTermSets: ReadonlyMap<string, readonly string[]> = new Map(
  Array.from(pinnedJsonLdContexts.entries(), ([contextUrl, document]) => {
    return [contextUrl, contextTermsFromPinnedDocument(document)] as const;
  }),
);
