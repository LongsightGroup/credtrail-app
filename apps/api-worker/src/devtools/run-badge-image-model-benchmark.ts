import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { resolve } from "node:path";
import { once } from "node:events";
import { z } from "zod";
import {
  BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES,
  buildBadgeImageModelBenchmarkPrompt,
  type BadgeImageModelBenchmarkSample,
} from "./badge-image-model-benchmark-samples";

type BenchmarkModelKey = "current" | "qwen";

type BenchmarkSuccess = {
  readonly status: "succeeded";
  readonly sampleId: string;
  readonly model: BenchmarkModelKey;
  readonly modelId: string;
  readonly modelRunMs: number;
  readonly assetFetchMs: number;
  readonly requestMs: number;
  readonly outputSizePx: number;
  readonly byteSize: number;
  readonly imageFilename: string;
};

type BenchmarkFailure = {
  readonly status: "failed";
  readonly sampleId: string;
  readonly model: BenchmarkModelKey;
  readonly requestMs: number;
  readonly error: string;
};

type BenchmarkResult = BenchmarkSuccess | BenchmarkFailure;

type TimingSummary = {
  readonly succeeded: number;
  readonly failed: number;
  readonly averageModelRunMs: number | null;
  readonly medianModelRunMs: number | null;
  readonly averageRequestMs: number | null;
};

const MODELS: ReadonlyArray<{
  readonly key: BenchmarkModelKey;
  readonly label: string;
  readonly invocation: string;
}> = [
  {
    key: "current",
    label: "Current · FLUX.2 Klein 9B",
    invocation: "Existing production path · 256×256 · 12 steps",
  },
  {
    key: "qwen",
    label: "Qwen Image 3.0 Pro",
    invocation: "Cloudflare unified model · 1024×1024 · prompt extension off",
  },
];

const REMOTE_WORKER_READY_TIMEOUT_MS = 90_000;
const GENERATION_REQUEST_TIMEOUT_MS = 240_000;

const benchmarkSuccessSchema = z.strictObject({
  status: z.literal("succeeded"),
  sampleId: z.string(),
  model: z.enum(["current", "qwen"]),
  modelId: z.string(),
  modelRunMs: z.number().nonnegative(),
  assetFetchMs: z.number().nonnegative(),
  requestMs: z.number().nonnegative(),
  outputSizePx: z.number().positive(),
  byteSize: z.number().positive(),
  imageFilename: z.string().min(1),
});

const benchmarkFailureSchema = z.strictObject({
  status: z.literal("failed"),
  sampleId: z.string(),
  model: z.enum(["current", "qwen"]),
  requestMs: z.number().nonnegative(),
  error: z.string(),
});

const savedReportSchema = z.object({
  results: z.array(
    z.discriminatedUnion("status", [benchmarkSuccessSchema, benchmarkFailureSchema]),
  ),
});

const generationErrorResponseSchema = z.object({
  error: z.string(),
  detail: z.string().optional(),
});

const benchmarkCliSchema = z.union([
  z.tuple([]),
  z.tuple([z.literal("--resume"), z.string().trim().min(1)]),
]);

const writeProgress = (message: string): void => {
  process.stdout.write(`${message}\n`);
};

const parseResumeDirectory = (): string | null => {
  const parsedArguments = benchmarkCliSchema.safeParse(process.argv.slice(2));

  if (!parsedArguments.success) {
    throw new Error(
      "Usage: pnpm benchmark:badge-images [-- --resume artifacts/badge-image-model-benchmark/<run>]",
    );
  }

  return parsedArguments.data.length === 0 ? null : resolve(parsedArguments.data[1]);
};

const resumableResults = async (outputDirectory: string): Promise<Array<BenchmarkSuccess>> => {
  const reportText = await readFile(resolve(outputDirectory, "report.json"), "utf8");
  const rawReport: unknown = JSON.parse(reportText);
  const report = savedReportSchema.parse(rawReport);
  const succeeded: Array<BenchmarkSuccess> = [];

  for (const result of report.results) {
    if (result.status !== "succeeded") {
      continue;
    }

    await access(resolve(outputDirectory, result.imageFilename));
    succeeded.push(result);
  }

  return succeeded;
};

const delay = async (milliseconds: number): Promise<void> => {
  await new Promise<void>((resolveDelay) => {
    setTimeout(resolveDelay, milliseconds);
  });
};

const availablePort = async (): Promise<number> => {
  const server = createServer();

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });

  const address = server.address();

  if (address === null || typeof address === "string") {
    server.close();
    throw new Error("Unable to reserve a local benchmark port");
  }

  const port = address.port;

  await new Promise<void>((resolveClose, rejectClose) => {
    server.close((cause) => {
      if (cause !== undefined) {
        rejectClose(cause);
        return;
      }

      resolveClose();
    });
  });

  return port;
};

const trimmedLog = (logChunks: ReadonlyArray<string>): string => {
  return logChunks.join("").slice(-4_000).trim();
};

const startRemoteWorker = async (
  port: number,
): Promise<{
  readonly child: ChildProcessWithoutNullStreams;
  readonly logs: Array<string>;
  readonly baseUrl: string;
}> => {
  const logs: Array<string> = [];
  const spawnFailure: { cause: Error | null } = { cause: null };
  const child = spawn(
    "pnpm",
    [
      "exec",
      "wrangler",
      "dev",
      "--remote",
      "--config",
      "wrangler.badge-image-benchmark.jsonc",
      "--port",
      String(port),
      "--show-interactive-dev-session",
      "false",
      "--log-level",
      "warn",
    ],
    {
      cwd: resolve("."),
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );

  const collectLog = (chunk: Uint8Array): void => {
    logs.push(new TextDecoder().decode(chunk));

    if (logs.length > 200) {
      logs.splice(0, logs.length - 200);
    }
  };

  child.stdout.on("data", collectLog);
  child.stderr.on("data", collectLog);
  child.once("error", (cause) => {
    spawnFailure.cause = cause;
  });

  const baseUrl = `http://127.0.0.1:${String(port)}`;
  const deadline = Date.now() + REMOTE_WORKER_READY_TIMEOUT_MS;

  while (Date.now() < deadline) {
    if (spawnFailure.cause !== null) {
      throw new Error(`Unable to start remote benchmark Worker: ${spawnFailure.cause.message}`);
    }

    if (child.exitCode !== null) {
      throw new Error(`Remote benchmark Worker exited early.\n${trimmedLog(logs)}`);
    }

    try {
      const response = await fetch(`${baseUrl}/health`, {
        signal: AbortSignal.timeout(2_000),
      });

      if (response.ok) {
        return { child, logs, baseUrl };
      }
    } catch {
      // The local proxy rejects requests until Wrangler finishes creating its remote preview.
    }

    await delay(500);
  }

  child.kill("SIGTERM");
  throw new Error(`Remote benchmark Worker did not become ready.\n${trimmedLog(logs)}`);
};

const stopRemoteWorker = async (child: ChildProcessWithoutNullStreams): Promise<void> => {
  if (child.exitCode !== null) {
    return;
  }

  child.kill("SIGTERM");
  const exited = once(child, "exit").then(() => true);
  const timedOut = delay(5_000).then(() => false);

  if (!(await Promise.race([exited, timedOut])) && child.exitCode === null) {
    child.kill("SIGKILL");
    await once(child, "exit");
  }
};

const responseError = async (response: Response): Promise<string> => {
  const responseText = (await response.text()).slice(0, 2_000).trim();

  if (responseText.length === 0) {
    return `HTTP ${String(response.status)}`;
  }

  try {
    const payload: unknown = JSON.parse(responseText);
    const parsed = generationErrorResponseSchema.safeParse(payload);

    if (!parsed.success) {
      return `HTTP ${String(response.status)}: ${responseText}`;
    }

    return parsed.data.detail === undefined
      ? parsed.data.error
      : `${parsed.data.error}: ${parsed.data.detail}`;
  } catch {
    return `HTTP ${String(response.status)}: ${responseText}`;
  }
};

const timingHeader = (response: Response, name: string): number => {
  const rawValue = response.headers.get(name);

  if (rawValue === null) {
    throw new Error(`Successful benchmark response omitted ${name}`);
  }

  const value = Number(rawValue);

  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`Successful benchmark response omitted ${name}`);
  }

  return value;
};

const imageExtension = (contentType: string): "png" | "jpg" | "webp" => {
  const normalized = contentType.split(";", 1)[0]?.trim().toLowerCase();

  switch (normalized) {
    case "image/png":
      return "png";
    case "image/jpeg":
      return "jpg";
    case "image/webp":
      return "webp";
    default:
      throw new Error(`Unsupported benchmark image content type: ${contentType}`);
  }
};

const runGeneration = async (input: {
  readonly baseUrl: string;
  readonly outputDirectory: string;
  readonly sample: BadgeImageModelBenchmarkSample;
  readonly sampleIndex: number;
  readonly model: BenchmarkModelKey;
}): Promise<BenchmarkResult> => {
  const startedAt = performance.now();

  try {
    const response = await fetch(`${input.baseUrl}/generate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sampleId: input.sample.id, model: input.model }),
      signal: AbortSignal.timeout(GENERATION_REQUEST_TIMEOUT_MS),
    });
    const requestMs = performance.now() - startedAt;

    if (!response.ok) {
      return {
        status: "failed",
        sampleId: input.sample.id,
        model: input.model,
        requestMs,
        error: await responseError(response),
      };
    }

    const contentType = response.headers.get("content-type") ?? "";
    const extension = imageExtension(contentType);
    const imageFilename = `${String(input.sampleIndex + 1).padStart(2, "0")}-${input.sample.id}-${input.model}.${extension}`;
    const bytes = new Uint8Array(await response.arrayBuffer());

    if (bytes.byteLength < 1) {
      throw new Error("Successful benchmark response returned an empty image");
    }

    await writeFile(resolve(input.outputDirectory, imageFilename), bytes);

    return {
      status: "succeeded",
      sampleId: input.sample.id,
      model: input.model,
      modelId: response.headers.get("x-credtrail-model-id") ?? "unknown",
      modelRunMs: timingHeader(response, "x-credtrail-model-run-ms"),
      assetFetchMs: timingHeader(response, "x-credtrail-asset-fetch-ms"),
      requestMs,
      outputSizePx: timingHeader(response, "x-credtrail-output-size-px"),
      byteSize: bytes.byteLength,
      imageFilename,
    };
  } catch (cause: unknown) {
    return {
      status: "failed",
      sampleId: input.sample.id,
      model: input.model,
      requestMs: performance.now() - startedAt,
      error: cause instanceof Error ? cause.message : "Unknown benchmark request failure",
    };
  }
};

const rounded = (value: number): number => Math.round(value * 10) / 10;

const summarizeTimings = (
  results: ReadonlyArray<BenchmarkResult>,
  model: BenchmarkModelKey,
): TimingSummary => {
  const modelResults = results.filter((result) => result.model === model);
  const succeeded = modelResults.filter(
    (result): result is BenchmarkSuccess => result.status === "succeeded",
  );
  const sortedModelTimes = succeeded.map((result) => result.modelRunMs).sort((a, b) => a - b);
  const middle = Math.floor(sortedModelTimes.length / 2);
  const medianValue =
    sortedModelTimes.length === 0
      ? null
      : sortedModelTimes.length % 2 === 0
        ? ((sortedModelTimes[middle - 1] ?? 0) + (sortedModelTimes[middle] ?? 0)) / 2
        : (sortedModelTimes[middle] ?? null);

  return {
    succeeded: succeeded.length,
    failed: modelResults.length - succeeded.length,
    averageModelRunMs:
      succeeded.length === 0
        ? null
        : rounded(
            succeeded.reduce((total, result) => total + result.modelRunMs, 0) / succeeded.length,
          ),
    medianModelRunMs: medianValue === null ? null : rounded(medianValue),
    averageRequestMs:
      succeeded.length === 0
        ? null
        : rounded(
            succeeded.reduce((total, result) => total + result.requestMs, 0) / succeeded.length,
          ),
  };
};

const escapeHtml = (value: string): string => {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
};

const formattedDuration = (milliseconds: number | null): string => {
  if (milliseconds === null) {
    return "—";
  }

  return `${(milliseconds / 1_000).toFixed(2)} s`;
};

const formattedBytes = (bytes: number): string => {
  return `${(bytes / 1_024).toFixed(0)} KB`;
};

const resultFor = (
  results: ReadonlyArray<BenchmarkResult>,
  sampleId: string,
  model: BenchmarkModelKey,
): BenchmarkResult | null => {
  return results.find((result) => result.sampleId === sampleId && result.model === model) ?? null;
};

const terminalModelFailure = (result: BenchmarkFailure): string | null => {
  return result.error.includes("Insufficient AI Gateway credits") ? result.error : null;
};

const renderModelResult = (
  sample: BadgeImageModelBenchmarkSample,
  model: (typeof MODELS)[number],
  result: BenchmarkResult | null,
  aboveFold: boolean,
): string => {
  if (result === null || result.status === "failed") {
    const error = result === null ? "No result was recorded." : result.error;
    return `<figure class="model-result model-result--failed">
      <div class="model-result__heading">
        <h3>${escapeHtml(model.label)}</h3>
        <span class="status status--failed">Failed</span>
      </div>
      <div class="image-failure" role="status">${escapeHtml(error)}</div>
      <figcaption>${escapeHtml(model.invocation)}</figcaption>
    </figure>`;
  }

  const loadingAttributes = aboveFold ? 'fetchpriority="high"' : 'loading="lazy" decoding="async"';

  return `<figure class="model-result">
    <div class="model-result__heading">
      <h3>${escapeHtml(model.label)}</h3>
      <span class="status status--succeeded">Generated</span>
    </div>
    <a class="image-frame" href="./${escapeHtml(result.imageFilename)}" target="_blank" rel="noreferrer">
      <img src="./${escapeHtml(result.imageFilename)}" alt="${escapeHtml(sample.title)} generated by ${escapeHtml(model.label)}" width="${String(result.outputSizePx)}" height="${String(result.outputSizePx)}" ${loadingAttributes}>
    </a>
    <dl class="timings">
      <div><dt>Model run</dt><dd>${formattedDuration(result.modelRunMs)}</dd></div>
      <div><dt>End to end</dt><dd>${formattedDuration(result.requestMs)}</dd></div>
      <div><dt>Output</dt><dd>${String(result.outputSizePx)} px · ${formattedBytes(result.byteSize)}</dd></div>
      ${result.assetFetchMs > 0 ? `<div><dt>Asset fetch</dt><dd>${formattedDuration(result.assetFetchMs)}</dd></div>` : ""}
    </dl>
    <figcaption>${escapeHtml(model.invocation)}</figcaption>
  </figure>`;
};

const renderReport = (input: {
  readonly generatedAt: string;
  readonly results: ReadonlyArray<BenchmarkResult>;
}): string => {
  const summaries = new Map<BenchmarkModelKey, TimingSummary>(
    MODELS.map((model) => [model.key, summarizeTimings(input.results, model.key)]),
  );
  const summaryRows = MODELS.map((model) => {
    const summary = summaries.get(model.key);

    if (summary === undefined) {
      throw new Error(`Missing timing summary for ${model.key}`);
    }

    return `<tr>
      <th scope="row">${escapeHtml(model.label)}</th>
      <td>${String(summary.succeeded)}/10</td>
      <td>${formattedDuration(summary.averageModelRunMs)}</td>
      <td>${formattedDuration(summary.medianModelRunMs)}</td>
      <td>${formattedDuration(summary.averageRequestMs)}</td>
    </tr>`;
  }).join("\n");
  const sampleSections = BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.map((sample, sampleIndex) => {
    const textTarget =
      sample.textRequirement.mode === "exact"
        ? `Required text: “${sample.textRequirement.text}”`
        : "Required text: none";

    return `<article class="sample">
      <header class="sample__header">
        <div>
          <p class="sample__position">Sample ${String(sampleIndex + 1)} of 10</p>
          <h2>${escapeHtml(sample.title)}</h2>
          <p>${escapeHtml(sample.description)}</p>
        </div>
        <dl class="sample__criteria">
          <div><dt>Review for</dt><dd>${escapeHtml(sample.evaluationFocus)}</dd></div>
          <div><dt>Text test</dt><dd>${escapeHtml(textTarget)}</dd></div>
        </dl>
      </header>
      <div class="comparison" aria-label="Model comparison for ${escapeHtml(sample.title)}">
        ${MODELS.map((model) =>
          renderModelResult(
            sample,
            model,
            resultFor(input.results, sample.id, model.key),
            sampleIndex === 0,
          ),
        ).join("\n")}
      </div>
      <details>
        <summary>Show identical prompt sent to both models</summary>
        <pre tabindex="0"><code>${escapeHtml(buildBadgeImageModelBenchmarkPrompt(sample))}</code></pre>
      </details>
    </article>`;
  }).join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CredTrail badge image model benchmark</title>
  <style>
    :root {
      color-scheme: light;
      --canvas: #f7fafd;
      --surface: #ffffff;
      --surface-soft: #eef4fb;
      --ink: #0d2543;
      --body: #173a5c;
      --muted: #536c86;
      --border: #c7d7e8;
      --border-strong: #91abc5;
      --blue: #0f5fa6;
      --blue-dark: #0b2748;
      --green: #166b46;
      --red: #ad3d31;
      --radius: 12px;
      font-family: "Avenir Next", "Segoe UI", system-ui, sans-serif;
    }
    * { box-sizing: border-box; }
    body { margin: 0; color: var(--body); background: var(--canvas); }
    header, main, footer { width: min(100% - 2rem, 90rem); margin-inline: auto; }
    .page-header { padding-block: 3rem 2rem; border-bottom: 1px solid var(--border); }
    h1, h2, h3, p { margin-top: 0; }
    h1, h2, h3 { color: var(--ink); letter-spacing: 0; text-wrap: balance; }
    h1 { max-width: 18ch; margin-bottom: 0.75rem; font-size: 2rem; line-height: 1.15; }
    .lede { max-width: 72ch; margin-bottom: 0; line-height: 1.65; }
    main { padding-block: 2rem 4rem; }
    .method { display: grid; gap: 1rem; margin-bottom: 2rem; }
    .method p { max-width: 75ch; margin-bottom: 0; line-height: 1.6; }
    .table-scroll { overflow-x: auto; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
    table { width: 100%; border-collapse: collapse; font-variant-numeric: tabular-nums; }
    th, td { padding: 0.8rem 1rem; border-bottom: 1px solid var(--border); text-align: left; white-space: nowrap; }
    thead th { color: var(--ink); background: var(--surface-soft); font-size: 0.82rem; }
    tbody th { color: var(--ink); font-size: 0.9rem; }
    tbody tr:last-child > * { border-bottom: 0; }
    .sample { padding-block: 2rem; border-top: 1px solid var(--border-strong); }
    .sample__header { width: 100%; display: flex; align-items: start; justify-content: space-between; gap: 2rem; margin: 0 0 1rem; }
    .sample__header h2 { margin-bottom: 0.35rem; font-size: 1.35rem; }
    .sample__header p { max-width: 65ch; margin-bottom: 0; line-height: 1.55; }
    .sample__position { color: var(--blue); font-size: 0.8rem; font-weight: 700; }
    .sample__criteria { min-width: 18rem; margin: 0; }
    .sample__criteria div { display: grid; grid-template-columns: 6rem 1fr; gap: 0.75rem; padding-block: 0.35rem; }
    dt { color: var(--muted); font-size: 0.78rem; font-weight: 700; }
    dd { margin: 0; color: var(--ink); font-size: 0.84rem; }
    .comparison { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1rem; }
    .model-result { min-width: 0; margin: 0; padding: 1rem; border: 1px solid var(--border); border-radius: var(--radius); background: var(--surface); }
    .model-result__heading { display: flex; align-items: center; justify-content: space-between; gap: 1rem; margin-bottom: 0.75rem; }
    .model-result h3 { margin-bottom: 0; font-family: inherit; font-size: 0.95rem; }
    .status { flex: 0 0 auto; border-radius: 999px; padding: 0.24rem 0.52rem; font-size: 0.72rem; font-weight: 700; }
    .status--succeeded { color: var(--green); background: #e7f4ed; }
    .status--failed { color: var(--red); background: #faecea; }
    .image-frame { display: grid; place-items: center; aspect-ratio: 1; overflow: hidden; border-radius: 8px; background: var(--surface-soft); }
    .image-frame:focus-visible, summary:focus-visible { outline: 3px solid #3a8fcb; outline-offset: 3px; }
    .image-frame img { display: block; width: 100%; height: 100%; object-fit: contain; }
    .image-failure { display: grid; place-items: center; min-height: 16rem; padding: 2rem; border: 1px solid #e7b7b0; border-radius: 8px; color: #7f2c24; background: #fff4f2; text-align: center; }
    .timings { display: flex; flex-wrap: wrap; gap: 0.45rem 1.25rem; margin: 0.85rem 0 0; font-variant-numeric: tabular-nums; }
    .timings div { display: flex; gap: 0.4rem; }
    .timings dd { font-weight: 700; }
    figcaption { margin-top: 0.65rem; color: var(--muted); font-size: 0.76rem; line-height: 1.4; }
    details { margin-top: 0.8rem; }
    summary { width: fit-content; color: var(--blue); cursor: pointer; font-size: 0.84rem; font-weight: 700; }
    pre { max-height: 20rem; overflow: auto; margin: 0.75rem 0 0; padding: 1rem; border-radius: 8px; color: #e9f2fb; background: var(--blue-dark); font: 0.78rem/1.55 ui-monospace, "SFMono-Regular", Consolas, monospace; white-space: pre-wrap; }
    footer { padding-block: 1.5rem 3rem; color: var(--muted); font-size: 0.8rem; }
    @media (max-width: 760px) {
      .page-header { padding-top: 2rem; }
      .comparison { grid-template-columns: minmax(0, 1fr); }
      .sample__header { display: grid; gap: 1rem; }
      .sample__criteria { min-width: 0; }
    }
    @media print {
      body { background: #fff; }
      header, main, footer { width: 100%; }
      .sample { break-inside: avoid; }
      details { display: none; }
    }
  </style>
</head>
<body>
  <header class="page-header">
    <h1>Badge image model benchmark</h1>
    <p class="lede">Ten controlled credential concepts generated once by each model. Review spelling, unwanted pseudo-text, emblem quality, crop safety, and small-size legibility alongside measured generation time.</p>
  </header>
  <main>
    <section class="method" aria-labelledby="timing-heading">
      <h2 id="timing-heading">Timing overview</h2>
      <p>Runs were sequential to avoid resource contention, and the first model alternated by sample to reduce order bias. “Model run” is measured inside the remote Worker around the model call. “End to end” includes the local request and, for Qwen, retrieval of its temporary image URL.</p>
      <div class="table-scroll">
        <table>
          <thead><tr><th scope="col">Model</th><th scope="col">Completed</th><th scope="col">Average model run</th><th scope="col">Median model run</th><th scope="col">Average end to end</th></tr></thead>
          <tbody>${summaryRows}</tbody>
        </table>
      </div>
    </section>
    ${sampleSections}
  </main>
  <footer>Generated ${escapeHtml(input.generatedAt)}. Raw measurements are in report.json.</footer>
</body>
</html>`;
};

const main = async (): Promise<void> => {
  const resumeDirectory = parseResumeDirectory();
  const generatedAt = new Date().toISOString();
  const runDirectoryName = generatedAt.replaceAll(":", "-").replaceAll(".", "-");
  const outputDirectory =
    resumeDirectory ?? resolve("artifacts", "badge-image-model-benchmark", runDirectoryName);
  await mkdir(outputDirectory, { recursive: true });
  const results: Array<BenchmarkResult> =
    resumeDirectory === null ? [] : await resumableResults(outputDirectory);

  const port = await availablePort();
  writeProgress("Starting a temporary Cloudflare remote-development Worker…");
  const remoteWorker = await startRemoteWorker(port);
  const terminalFailures = new Map<BenchmarkModelKey, string>();
  let runPosition = 0;

  try {
    for (const [sampleIndex, sample] of BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.entries()) {
      const modelOrder: ReadonlyArray<BenchmarkModelKey> =
        sampleIndex % 2 === 0 ? ["current", "qwen"] : ["qwen", "current"];

      for (const model of modelOrder) {
        runPosition += 1;
        const modelLabel = MODELS.find((candidate) => candidate.key === model)?.label ?? model;
        const existingResult = resultFor(results, sample.id, model);

        if (existingResult?.status === "succeeded") {
          writeProgress(
            `[${String(runPosition).padStart(2, "0")}/20] ${sample.title} · ${modelLabel} · reused`,
          );
          continue;
        }

        const terminalFailure = terminalFailures.get(model);

        if (terminalFailure !== undefined) {
          results.push({
            status: "failed",
            sampleId: sample.id,
            model,
            requestMs: 0,
            error: `Skipped after terminal model failure: ${terminalFailure}`,
          });
          writeProgress(
            `[${String(runPosition).padStart(2, "0")}/20] ${sample.title} · ${modelLabel} · skipped`,
          );
          continue;
        }

        writeProgress(
          `[${String(runPosition).padStart(2, "0")}/20] ${sample.title} · ${modelLabel}`,
        );
        const result = await runGeneration({
          baseUrl: remoteWorker.baseUrl,
          outputDirectory,
          sample,
          sampleIndex,
          model,
        });
        results.push(result);

        if (result.status === "succeeded") {
          writeProgress(
            `     model ${formattedDuration(result.modelRunMs)} · end to end ${formattedDuration(result.requestMs)}`,
          );
        } else {
          writeProgress(`     failed · ${result.error}`);
          const terminalFailureDetail = terminalModelFailure(result);

          if (terminalFailureDetail !== null) {
            terminalFailures.set(model, terminalFailureDetail);
          }
        }
      }
    }
  } finally {
    await stopRemoteWorker(remoteWorker.child);
  }

  const reportData = {
    generatedAt,
    methodology: {
      sampleCount: BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.length,
      runsPerModel: BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.length,
      execution: "sequential with alternating model order",
      resumed: resumeDirectory !== null,
    },
    models: MODELS,
    samples: BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.map((sample) => ({
      ...sample,
      prompt: buildBadgeImageModelBenchmarkPrompt(sample),
    })),
    summaries: Object.fromEntries(
      MODELS.map((model) => [model.key, summarizeTimings(results, model.key)]),
    ),
    results,
  };
  const reportPath = resolve(outputDirectory, "report.html");
  await Promise.all([
    writeFile(reportPath, renderReport({ generatedAt, results }), "utf8"),
    writeFile(resolve(outputDirectory, "report.json"), JSON.stringify(reportData, null, 2), "utf8"),
  ]);

  writeProgress(`\nReport: ${reportPath}`);
  writeProgress(`Data:   ${resolve(outputDirectory, "report.json")}`);

  const failures = results.filter((result) => result.status === "failed");

  if (failures.length > 0) {
    process.exitCode = 1;
    writeProgress(
      `${String(failures.length)} of 20 generations failed; successful results remain in the report.`,
    );
  }
};

main().catch((cause: unknown) => {
  const detail = cause instanceof Error ? cause.message : "Unknown benchmark failure";
  process.stderr.write(`Badge image benchmark failed: ${detail}\n`);
  process.exitCode = 1;
});
