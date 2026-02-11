import { mkdirSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const QUALITY_COMMANDS = [
  {
    label: 'lint',
    command: 'pnpm',
    args: ['lint'],
  },
  {
    label: 'typecheck',
    command: 'pnpm',
    args: ['typecheck'],
  },
  {
    label: 'api-worker tests',
    command: 'pnpm',
    args: ['test', '--', 'apps/api-worker/src/index.test.ts'],
  },
];

const runCommand = ({ label, command, args }) => {
  process.stdout.write(`\n[ob3-cert] Running ${label}: ${command} ${args.join(' ')}\n`);
  const result = spawnSync(command, args, {
    stdio: 'inherit',
    shell: false,
  });

  if (result.status !== 0) {
    throw new Error(`${label} failed with exit code ${String(result.status)}`);
  }
};

const sleep = (milliseconds) => {
  return new Promise((resolvePromise) => {
    setTimeout(resolvePromise, milliseconds);
  });
};

const jsonBodyFromResponse = async (response) => {
  const responseText = await response.text();

  if (responseText.trim().length === 0) {
    return {};
  }

  try {
    return JSON.parse(responseText);
  } catch {
    return {
      _raw: responseText,
    };
  }
};

const asObject = (value) => {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    return null;
  }

  return value;
};

const asString = (value) => {
  return typeof value === 'string' ? value : null;
};

const requestJson = async ({ baseUrl, path, method, headers, body }) => {
  const response = await fetch(new URL(path, baseUrl), {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const responseBody = await jsonBodyFromResponse(response);

  if (!response.ok) {
    throw new Error(
      `Request failed: ${method} ${path} -> ${String(response.status)} ${JSON.stringify(responseBody)}`,
    );
  }

  return responseBody;
};

const runLiveCertificationSmokeTest = async () => {
  const baseUrlValue = process.env.CERT_BASE_URL;

  if (baseUrlValue === undefined || baseUrlValue.trim().length === 0) {
    process.stdout.write('\n[ob3-cert] CERT_BASE_URL is not set; skipping live issuance smoke test.\n');
    return null;
  }

  const bootstrapToken = process.env.CERT_BOOTSTRAP_ADMIN_TOKEN;

  if (bootstrapToken === undefined || bootstrapToken.trim().length === 0) {
    throw new Error('CERT_BOOTSTRAP_ADMIN_TOKEN is required when CERT_BASE_URL is set');
  }

  const baseUrl = new URL(baseUrlValue.trim());
  const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, '');
  const tenantId = process.env.CERT_TENANT_ID?.trim() || 'ob3cert';
  const badgeTemplateId = process.env.CERT_BADGE_TEMPLATE_ID?.trim() || 'badge_template_ob3_cert';
  const keyId = process.env.CERT_KEY_ID?.trim() || `ob3-cert-key-${timestamp}`;
  const issuerDid =
    process.env.CERT_ISSUER_DID?.trim() || `did:web:${baseUrl.hostname}:${encodeURIComponent(tenantId)}`;
  const recipientEmail = process.env.CERT_RECIPIENT_EMAIL?.trim() || 'conformance@imsglobal.org';
  const idempotencyKey = process.env.CERT_IDEMPOTENCY_KEY?.trim() || `ob3-cert-${timestamp}`;
  const adminHeaders = {
    authorization: `Bearer ${bootstrapToken.trim()}`,
    'content-type': 'application/json',
  };

  process.stdout.write('\n[ob3-cert] Running live issuance smoke test against configured deployment.\n');

  const generatedKeyResponse = await requestJson({
    baseUrl,
    path: '/v1/signing/keys/generate',
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: {
      did: issuerDid,
      keyId,
    },
  });
  const generatedKeyObject = asObject(generatedKeyResponse);
  const keyMaterial = asObject(generatedKeyObject?.keyMaterial);
  const publicJwk = asObject(keyMaterial?.publicJwk);
  const privateJwk = asObject(keyMaterial?.privateJwk);
  const resolvedKeyId = asString(keyMaterial?.keyId);

  if (publicJwk === null || privateJwk === null || resolvedKeyId === null) {
    throw new Error('Signing key generation response did not include expected key material');
  }

  await requestJson({
    baseUrl,
    path: `/v1/admin/tenants/${encodeURIComponent(tenantId)}`,
    method: 'PUT',
    headers: adminHeaders,
    body: {
      slug: tenantId,
      displayName: 'OB3 Certification Tenant',
      planTier: 'team',
      issuerDomain: `${tenantId}.${baseUrl.hostname}`,
      isActive: true,
    },
  });

  await requestJson({
    baseUrl,
    path: `/v1/admin/tenants/${encodeURIComponent(tenantId)}/signing-registration`,
    method: 'PUT',
    headers: adminHeaders,
    body: {
      keyId: resolvedKeyId,
      publicJwk,
      privateJwk,
    },
  });

  await requestJson({
    baseUrl,
    path: `/v1/admin/tenants/${encodeURIComponent(tenantId)}/badge-templates/${encodeURIComponent(badgeTemplateId)}`,
    method: 'PUT',
    headers: adminHeaders,
    body: {
      slug: 'ob3-certification-badge',
      title: 'OB3 Certification Test Badge',
      description: 'Issued for Open Badges 3.0 issuer conformance validation.',
      criteriaUri: 'https://example.org/ob3/certification/criteria',
      imageUri: 'https://example.org/ob3/certification/image.png',
    },
  });

  const issueResponse = await requestJson({
    baseUrl,
    path: '/v1/issue',
    method: 'POST',
    headers: {
      'content-type': 'application/json',
    },
    body: {
      tenantId,
      badgeTemplateId,
      recipientIdentity: recipientEmail,
      recipientIdentityType: 'email',
      idempotencyKey,
    },
  });
  const issueObject = asObject(issueResponse);
  const assertionId = asString(issueObject?.assertionId);

  if (assertionId === null) {
    throw new Error('Issue endpoint did not return assertionId');
  }

  const jobProcessorToken = process.env.CERT_JOB_PROCESSOR_TOKEN?.trim();
  const processorHeaders = {
    'content-type': 'application/json',
    ...(jobProcessorToken === undefined || jobProcessorToken.length === 0
      ? {}
      : { authorization: `Bearer ${jobProcessorToken}` }),
  };

  await requestJson({
    baseUrl,
    path: '/v1/jobs/process',
    method: 'POST',
    headers: processorHeaders,
    body: {
      limit: 20,
      leaseSeconds: 60,
      retryDelaySeconds: 5,
    },
  });

  const encodedAssertionId = encodeURIComponent(assertionId);
  let verificationBody = null;

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const verificationResponse = await fetch(new URL(`/credentials/v1/${encodedAssertionId}`, baseUrl));

    if (verificationResponse.status === 404) {
      await sleep(1000);
      continue;
    }

    if (!verificationResponse.ok) {
      const failedVerificationBody = await jsonBodyFromResponse(verificationResponse);
      throw new Error(
        `Verification endpoint failed: ${String(verificationResponse.status)} ${JSON.stringify(failedVerificationBody)}`,
      );
    }

    verificationBody = await jsonBodyFromResponse(verificationResponse);
    break;
  }

  const verificationObject = asObject(verificationBody);
  const verification = asObject(verificationObject?.verification);
  const verificationStatus = asString(verification?.status);
  const checks = asObject(verification?.checks);
  const credentialSubjectCheck = asObject(checks?.credentialSubject);
  const credentialSubjectStatus = asString(credentialSubjectCheck?.status);

  if (verificationStatus !== 'active') {
    throw new Error(`Expected active verification status, got: ${JSON.stringify(verificationStatus)}`);
  }

  if (credentialSubjectStatus !== 'valid') {
    throw new Error(`Expected valid credentialSubject check, got: ${JSON.stringify(credentialSubjectStatus)}`);
  }

  const jsonldResponse = await fetch(new URL(`/credentials/v1/${encodedAssertionId}/jsonld`, baseUrl));

  if (!jsonldResponse.ok) {
    const jsonldBody = await jsonBodyFromResponse(jsonldResponse);
    throw new Error(`JSON-LD retrieval failed: ${String(jsonldResponse.status)} ${JSON.stringify(jsonldBody)}`);
  }

  const badgePagePath = `/badges/${encodedAssertionId}`;
  const verificationPath = `/credentials/v1/${encodedAssertionId}`;
  const downloadPath = `/credentials/v1/${encodedAssertionId}/download`;
  const jsonldPath = `/credentials/v1/${encodedAssertionId}/jsonld`;

  return {
    baseUrl: baseUrl.toString(),
    tenantId,
    badgeTemplateId,
    issuerDid,
    keyId: resolvedKeyId,
    recipientEmail,
    assertionId,
    badgePageUrl: new URL(badgePagePath, baseUrl).toString(),
    verificationUrl: new URL(verificationPath, baseUrl).toString(),
    credentialDownloadUrl: new URL(downloadPath, baseUrl).toString(),
    credentialJsonLdUrl: new URL(jsonldPath, baseUrl).toString(),
    verificationSummary: {
      status: verificationStatus,
      credentialSubjectStatus,
      checkedAt: asString(verification?.checkedAt),
    },
  };
};

const main = async () => {
  const skipLocalChecks = process.argv.includes('--skip-local');
  const runLiveOnly = process.argv.includes('--live-only');

  if (!runLiveOnly) {
    if (skipLocalChecks) {
      process.stdout.write('[ob3-cert] Local quality checks skipped by flag.\n');
    } else {
      for (const command of QUALITY_COMMANDS) {
        runCommand(command);
      }
    }
  }

  const liveEvidence = await runLiveCertificationSmokeTest();
  const outputDirectory = resolve('artifacts', 'ob3-certification');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outputPath = resolve(outputDirectory, `preflight-${timestamp}.json`);

  mkdirSync(outputDirectory, {
    recursive: true,
  });

  const report = {
    generatedAt: new Date().toISOString(),
    localChecksExecuted: runLiveOnly ? false : !skipLocalChecks,
    liveCheckExecuted: liveEvidence !== null,
    liveEvidence,
  };

  writeFileSync(outputPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  process.stdout.write(`\n[ob3-cert] Wrote preflight report: ${outputPath}\n`);
};

main().catch((error) => {
  process.stderr.write(`\n[ob3-cert] FAILED: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
