# LMS Setup Guide

CredTrail runs as an LTI 1.3 Advantage tool. Use this guide to configure Canvas
and Sakai pilots against a CredTrail environment.

## CredTrail Tool Values

Replace `https://credtrail.example.edu` with the environment under test.

| Field | Value |
| --- | --- |
| OIDC login initiation URL | `https://credtrail.example.edu/v1/lti/oidc/login` |
| Launch / redirect URI | `https://credtrail.example.edu/v1/lti/launch` |
| Tool JWKS URL | `https://credtrail.example.edu/v1/lti/jwks` |
| Deep Linking response mode | Signed LTI 1.3 Deep Linking Response JWT |

After the LMS tool is created, add or update the issuer registration in
CredTrail admin with the LMS issuer, client ID, authorization endpoint, platform
JWKS endpoint, and token endpoint. Signed launches require both platform JWKS
and token endpoint metadata.

## Canvas

1. Create or edit a Canvas Developer Key for LTI 1.3.
2. Set the tool method to manual entry.
3. Enter the CredTrail OIDC login initiation URL, launch URL, and JWKS URL from
   the table above.
4. Enable LTI placements needed for the pilot:
   - Course Navigation for resource-link launches.
   - Assignment Selection or Link Selection for Deep Linking.
5. Enable LTI Advantage services required by the pilot:
   - Deep Linking.
   - Names and Role Provisioning Services if roster-based issuance is required.
6. Save the Developer Key and copy the Canvas `client_id`.
7. Install the tool in the target account or course.
8. In CredTrail admin, create the issuer registration with:
   - Canvas issuer URL.
   - CredTrail tenant ID.
   - Canvas authorization endpoint.
   - Canvas `client_id`.
   - Canvas platform JWKS endpoint.
   - Canvas token endpoint.
9. Launch the tool from Canvas and confirm CredTrail shows either the LTI launch
   completion page or the Deep Linking template picker.

For live Canvas validation, use [CANVAS_REAL_INSTANCE_E2E.md](./CANVAS_REAL_INSTANCE_E2E.md).

## Sakai

1. Create or edit an External Tool / LTI 1.3 tool registration in Sakai.
2. Enter the CredTrail OIDC login initiation URL, launch URL, and JWKS URL from
   the table above.
3. Enable signed LTI 1.3 launches and configure Sakai to use CredTrail's JWKS
   URL for tool key discovery.
4. Enable Deep Linking if instructors should place badge templates from Sakai.
5. Enable Names and Role Provisioning Services when roster-based badge issuance
   is required.
6. Copy the Sakai issuer, client ID, authorization endpoint, platform JWKS
   endpoint, token endpoint, and deployment ID.
7. In CredTrail admin, create the issuer registration with the Sakai values and
   target tenant ID.
8. Start with a baseline launch. Then validate Deep Linking and NRPS only after
   the baseline signed launch succeeds.

For live Sakai validation, use [SAKAI_REAL_INSTANCE_E2E.md](./SAKAI_REAL_INSTANCE_E2E.md).

## Troubleshooting

- OIDC initiation errors usually mean issuer, client ID, authorization endpoint,
  or target link URI values do not match between the LMS and CredTrail.
- Launch verification errors usually mean the platform JWKS endpoint is missing
  or does not expose the key currently used by the LMS.
- Deep Linking failures usually mean the launch did not include
  `deep_linking_settings.deep_link_return_url` or the placement was not enabled
  in the LMS.
- NRPS failures usually mean roster service access is disabled or the platform
  token endpoint is missing.
