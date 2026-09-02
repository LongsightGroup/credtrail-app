import type { SqlDatabase, TenantMembershipRole } from "@credtrail/db";
import type { AppContext } from "../app/types";
import type { LtiAuthenticatedPrincipal, LtiSessionInput } from "../auth/auth-provider";
import type { LinkedLtiLaunchAccount } from "./launch-account-linking";
import type { ResolvedLtiLaunchMessage } from "./launch-message";
import type { ResolvedLtiLaunch } from "./launch-verification";
import type {
  UnresolvedResourceLinkLaunch,
  ValidatedResourceLinkLaunch,
} from "./resource-link-launch-types";

export type DeepLinkingLaunchMessage = Extract<ResolvedLtiLaunchMessage, { kind: "deep-linking" }>;

export interface HandleVerifiedLtiLaunchInput {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  resolvedLaunch: ResolvedLtiLaunch;
  launchMessage: ResolvedLtiLaunchMessage;
  sha256Hex: (value: string) => Promise<string>;
  createLtiSession: (
    context: AppContext,
    input: LtiSessionInput,
  ) => Promise<LtiAuthenticatedPrincipal>;
}

export type HandleVerifiedLtiLaunch = (input: HandleVerifiedLtiLaunchInput) => Promise<Response>;

export interface ProductFlowFailure {
  status: 400 | 403 | 409 | 500;
  surface?: "lti_rule_unavailable" | undefined;
  body: {
    error: string;
    reason?: string;
    detail?: string;
  };
}

export type ProductFlowResult<TValue> =
  | {
      ok: true;
      value: TValue;
    }
  | {
      ok: false;
      failure: ProductFlowFailure;
    };

export interface ValidatedDeepLinkingLaunch {
  launchMessage: DeepLinkingLaunchMessage;
}

export type ValidatedLtiLaunchMessage = ValidatedDeepLinkingLaunch | UnresolvedResourceLinkLaunch;

export interface EstablishedLtiLaunchSession {
  linkedAccount: LinkedLtiLaunchAccount;
  createdSession: LtiAuthenticatedPrincipal;
}

export interface PreparedResourceLinkLaunch {
  launch: ValidatedResourceLinkLaunch;
}

export interface PrepareLaunchedResourceLinkPlacementInput {
  c: AppContext;
  db: SqlDatabase;
  tenantId: string;
  issuerEntryClientId: string;
  launchClaims: ResolvedLtiLaunch["launchClaims"];
  resolvedLaunch: ResolvedLtiLaunch;
  launch: UnresolvedResourceLinkLaunch;
  linkedUserId: string;
  linkedMembershipRole: TenantMembershipRole;
}

export const productFlowSuccess = <TValue>(value: TValue): ProductFlowResult<TValue> => ({
  ok: true,
  value,
});

export const productFlowFailure = (failure: ProductFlowFailure): ProductFlowResult<never> => ({
  ok: false,
  failure,
});
