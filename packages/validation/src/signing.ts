import { z } from "zod";
import { jsonObjectSchema } from "./json.js";

export const didWebSchema = z.string().startsWith("did:web:");

export const ed25519PublicJwkSchema = z.object({
  kty: z.literal("OKP"),
  crv: z.literal("Ed25519"),
  x: z.string().min(1),
  kid: z.string().min(1).optional(),
});

export const ed25519PrivateJwkSchema = ed25519PublicJwkSchema.extend({
  d: z.string().min(1),
});

export const p256PublicJwkSchema = z.object({
  kty: z.literal("EC"),
  crv: z.literal("P-256"),
  x: z.string().min(1),
  y: z.string().min(1),
  kid: z.string().min(1).optional(),
});

export const p256PrivateJwkSchema = p256PublicJwkSchema.extend({
  d: z.string().min(1),
});

const tenantSigningRegistryEntryEd25519Schema = z.object({
  tenantId: z.string().min(1),
  keyId: z.string().min(1),
  publicJwk: ed25519PublicJwkSchema,
  privateJwk: ed25519PrivateJwkSchema.optional(),
});

const tenantSigningRegistryEntryP256Schema = z.object({
  tenantId: z.string().min(1),
  keyId: z.string().min(1),
  publicJwk: p256PublicJwkSchema,
  privateJwk: p256PrivateJwkSchema.optional(),
});

export const tenantSigningRegistryEntrySchema = z.union([
  tenantSigningRegistryEntryEd25519Schema,
  tenantSigningRegistryEntryP256Schema,
]);

export const tenantSigningRegistrySchema = z.record(
  z.string().min(1),
  tenantSigningRegistryEntrySchema,
);

export const keyGenerationRequestSchema = z.object({
  did: didWebSchema,
  keyId: z.string().min(1).max(128).optional(),
});

export const signCredentialRequestSchema = z
  .object({
    did: didWebSchema,
    credential: jsonObjectSchema,
    proofType: z.literal("DataIntegrityProof").optional(),
    cryptosuite: z.literal("eddsa-rdfc-2022").optional(),
  })
  .superRefine((value, ctx) => {
    if (value.proofType !== "DataIntegrityProof" && value.cryptosuite !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["cryptosuite"],
        message: "cryptosuite is only allowed when proofType is DataIntegrityProof",
      });
    }
  });

export const bootstrapSigningRegistrationRequestSchema = z.object({
  keyId: z.string().trim().min(1).max(128),
  publicJwk: ed25519PublicJwkSchema,
  privateJwk: ed25519PrivateJwkSchema.optional(),
});
// --- inferred types and parsers ---
export type KeyGenerationRequest = z.infer<typeof keyGenerationRequestSchema>;

export type SignCredentialRequest = z.infer<typeof signCredentialRequestSchema>;

export type BootstrapSigningRegistrationRequest = z.infer<
  typeof bootstrapSigningRegistrationRequestSchema
>;

export type TenantSigningRegistry = z.infer<typeof tenantSigningRegistrySchema>;

export type TenantSigningRegistryEntry = z.infer<typeof tenantSigningRegistryEntrySchema>;

export const parseKeyGenerationRequest = (input: unknown): KeyGenerationRequest => {
  return keyGenerationRequestSchema.parse(input);
};

export const parseSignCredentialRequest = (input: unknown): SignCredentialRequest => {
  return signCredentialRequestSchema.parse(input);
};

export const parseBootstrapSigningRegistrationRequest = (
  input: unknown,
): BootstrapSigningRegistrationRequest => {
  return bootstrapSigningRegistrationRequestSchema.parse(input);
};

export const parseTenantSigningRegistry = (input: unknown): TenantSigningRegistry => {
  return tenantSigningRegistrySchema.parse(input);
};

export const parseTenantSigningRegistryEntry = (input: unknown): TenantSigningRegistryEntry => {
  return tenantSigningRegistryEntrySchema.parse(input);
};
