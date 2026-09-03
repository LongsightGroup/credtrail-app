import { describe, expect, it } from "vitest";
import {
  BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES,
  buildBadgeImageModelBenchmarkPrompt,
} from "./badge-image-model-benchmark-samples";

describe("badge image model benchmark samples", () => {
  it("keeps a fixed set of ten unique badge concepts", () => {
    const ids = BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.map((sample) => sample.id);

    expect(ids).toHaveLength(10);
    expect(new Set(ids).size).toBe(10);
  });

  it("gives exact-text samples explicit spelling constraints", () => {
    const sample = BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.find(
      (candidate) => candidate.id === "research-integrity",
    );

    if (sample === undefined) {
      throw new Error("Expected the research-integrity benchmark sample");
    }

    const prompt = buildBadgeImageModelBenchmarkPrompt(sample);

    expect(prompt).toContain('render the exact text "Research Integrity" once');
    expect(prompt).toContain("spell it exactly as written");
    expect(prompt).toContain("Do not add any other letters");
  });

  it("tells no-text samples to avoid pseudo-text", () => {
    const sample = BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.find(
      (candidate) => candidate.id === "climate-action",
    );

    if (sample === undefined) {
      throw new Error("Expected the climate-action benchmark sample");
    }

    const prompt = buildBadgeImageModelBenchmarkPrompt(sample);

    expect(prompt).toContain("render no letters, words, numbers");
    expect(prompt).toContain("pseudo-text");
  });
});
