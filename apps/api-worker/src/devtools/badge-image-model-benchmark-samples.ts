/** A controlled badge-artwork prompt used to compare image models. */
export type BadgeImageModelBenchmarkSample = {
  readonly id: string;
  readonly title: string;
  readonly description: string;
  readonly stylePreset: "institutional" | "technical" | "academic" | "open_source" | "minimal";
  readonly accentColor: string;
  readonly visualDirection: string;
  readonly evaluationFocus: string;
  readonly textRequirement:
    | { readonly mode: "none" }
    | { readonly mode: "exact"; readonly text: string };
};

/** The ten fixed concepts used for every badge-image model comparison. */
export const BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES: ReadonlyArray<BadgeImageModelBenchmarkSample> = [
  {
    id: "ai-literacy",
    title: "AI Literacy",
    description: "Recognizes practical understanding of responsible generative AI use.",
    stylePreset: "technical",
    accentColor: "deep lake blue and warm gold",
    visualDirection: "A simple spark-and-circuit emblem with generous space around the title.",
    evaluationFocus: "Exact short title",
    textRequirement: { mode: "exact", text: "AI Literacy" },
  },
  {
    id: "research-integrity",
    title: "Research Integrity",
    description: "Recognizes ethical, transparent, and reproducible research practice.",
    stylePreset: "academic",
    accentColor: "midnight blue and mint green",
    visualDirection: "A checkmark integrated with a simple microscope or open research notebook.",
    evaluationFocus: "Exact longer title",
    textRequirement: { mode: "exact", text: "Research Integrity" },
  },
  {
    id: "community-leadership",
    title: "Community Leadership",
    description: "Recognizes collaborative leadership and service to a campus community.",
    stylePreset: "institutional",
    accentColor: "navy blue and warm gold",
    visualDirection: "A centered bridge or three connected figures in a formal medallion.",
    evaluationFocus: "Exact multiword title",
    textRequirement: { mode: "exact", text: "Community Leadership" },
  },
  {
    id: "lab-safety",
    title: "Lab Safety",
    description: "Recognizes safe preparation and responsible conduct in a teaching laboratory.",
    stylePreset: "academic",
    accentColor: "lake blue and amber",
    visualDirection: "Protective goggles above a small flask, with a clear checkmark.",
    evaluationFocus: "Exact title and icon balance",
    textRequirement: { mode: "exact", text: "Lab Safety" },
  },
  {
    id: "applied-analytics",
    title: "Applied Analytics",
    description: "Recognizes using data analysis to answer a practical institutional question.",
    stylePreset: "technical",
    accentColor: "royal blue and mint green",
    visualDirection: "A clean upward chart combined with a magnifying glass.",
    evaluationFocus: "Exact title and small-size clarity",
    textRequirement: { mode: "exact", text: "Applied Analytics" },
  },
  {
    id: "cpr-certified",
    title: "CPR Certified",
    description: "Recognizes completion of cardiopulmonary resuscitation training.",
    stylePreset: "minimal",
    accentColor: "deep blue and clear red",
    visualDirection: "A simple heart-and-pulse emblem with the initials as the central text.",
    evaluationFocus: "Exact three-letter initials",
    textRequirement: { mode: "exact", text: "CPR" },
  },
  {
    id: "first-year-mentor",
    title: "First-Year Mentor",
    description: "Recognizes peer guidance for students entering their first year.",
    stylePreset: "institutional",
    accentColor: "midnight blue and sun gold",
    visualDirection: "A friendly compass-star mark with the initials centered beneath it.",
    evaluationFocus: "Exact initials",
    textRequirement: { mode: "exact", text: "FYM" },
  },
  {
    id: "inclusive-course-design",
    title: "Inclusive Course Design",
    description: "Recognizes accessible and inclusive design of learning experiences.",
    stylePreset: "academic",
    accentColor: "lake blue and violet",
    visualDirection: "An open book whose pages form three welcoming paths.",
    evaluationFocus: "No stray or pseudo-text",
    textRequirement: { mode: "none" },
  },
  {
    id: "cybersecurity-essentials",
    title: "Cybersecurity Essentials",
    description: "Recognizes foundational skill in protecting systems and information.",
    stylePreset: "technical",
    accentColor: "midnight blue and bright cyan",
    visualDirection: "A bold shield containing a simple keyhole and one circuit line.",
    evaluationFocus: "No stray or pseudo-text",
    textRequirement: { mode: "none" },
  },
  {
    id: "climate-action",
    title: "Climate Action",
    description: "Recognizes meaningful work toward campus sustainability goals.",
    stylePreset: "open_source",
    accentColor: "forest green and lake blue",
    visualDirection: "A single leaf wrapping around a simplified globe.",
    evaluationFocus: "No stray or pseudo-text",
    textRequirement: { mode: "none" },
  },
];

/** Builds one identical, production-shaped comparison prompt for both models. */
export const buildBadgeImageModelBenchmarkPrompt = (
  sample: BadgeImageModelBenchmarkSample,
): string => {
  const textDirection =
    sample.textRequirement.mode === "exact"
      ? [
          `Typography requirement: render the exact text "${sample.textRequirement.text}" once and spell it exactly as written.`,
          "Do not add any other letters, words, captions, labels, or pseudo-text.",
          "Make the required text large, high-contrast, and legible when the badge is displayed at 128 by 128 pixels.",
        ]
      : [
          "Typography requirement: render no letters, words, numbers, captions, labels, or pseudo-text anywhere in the image.",
        ];

  return [
    "Create a polished square badge icon for a higher-education digital credential.",
    "The result should feel like an official achievement token: calm, modern, academic, and trustworthy.",
    "Use one centered emblem with clean vector-like geometry, strong contrast, restrained detail, and a simple solid background.",
    "Do not create a certificate, poster, web page, document, screenshot, product logo, or photorealistic scene.",
    `Badge concept: ${sample.title}.`,
    `Achievement meaning: ${sample.description}`,
    `Visual style: ${sample.stylePreset}.`,
    `Color direction: ${sample.accentColor}.`,
    `Composition direction: ${sample.visualDirection}`,
    ...textDirection,
    "Keep all important content within a generous safe area so it will not be cropped in a circular or rounded-square presentation.",
    "Return one finished badge image and nothing else.",
  ].join("\n");
};

/** Finds a benchmark sample by its stable request identifier. */
export const findBadgeImageModelBenchmarkSample = (
  sampleId: string,
): BadgeImageModelBenchmarkSample | null => {
  return BADGE_IMAGE_MODEL_BENCHMARK_SAMPLES.find((sample) => sample.id === sampleId) ?? null;
};
