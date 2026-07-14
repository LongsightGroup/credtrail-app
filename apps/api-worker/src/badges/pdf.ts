import {
  PDFDocument,
  StandardFonts,
  rgb,
  type PDFImage,
  type PDFFont,
  type PDFPage,
} from "pdf-lib";

import { withCredTrailUserAgent } from "../http/outbound-user-agent";
import { createQrCodeMatrix } from "./qr-code";

export const badgeInitialsFromName = (badgeName: string): string => {
  const trimmedName = badgeName.trim();

  if (trimmedName.length === 0) {
    return "BD";
  }

  const words = trimmedName.split(/\s+/).filter((word) => word.length > 0);
  const firstWord = words.at(0);

  if (firstWord === undefined) {
    return "BD";
  }

  const secondWord = words.at(1);
  const firstInitial = firstWord.slice(0, 1);
  const secondInitial = secondWord === undefined ? firstWord.slice(1, 2) : secondWord.slice(0, 1);
  const initials = `${firstInitial}${secondInitial}`.replaceAll(/[^a-zA-Z0-9]/g, "").toUpperCase();

  return initials.length === 0 ? "BD" : initials;
};

export const credentialDownloadFilename = (assertionId: string): string => {
  const safeAssertionId = assertionId.replaceAll(/[^a-zA-Z0-9_-]+/g, "-").replaceAll(/-+/g, "-");
  const trimmed = safeAssertionId.replaceAll(/^-|-$/g, "");
  const fallback = trimmed.length === 0 ? "badge" : trimmed;

  return `${fallback}.jsonld`;
};

export const credentialPdfDownloadFilename = (assertionId: string): string => {
  const safeAssertionId = assertionId.replaceAll(/[^a-zA-Z0-9_-]+/g, "-").replaceAll(/-+/g, "-");
  const trimmed = safeAssertionId.replaceAll(/^-|-$/g, "");
  const fallback = trimmed.length === 0 ? "badge" : trimmed;

  return `${fallback}.pdf`;
};

export interface BadgePdfDocumentInput {
  badgeName: string;
  recipientName: string;
  recipientIdentifier: string;
  issuerName: string;
  issuedAt: string;
  status: string;
  assertionId: string;
  credentialId: string;
  publicBadgeUrl: string;
  verificationUrl: string;
  ob3JsonUrl: string;
  badgeImageUrl: string | null;
  revokedAt?: string;
}

interface BadgePdfImageAsset {
  bytes: Uint8Array;
  mimeType: "image/png" | "image/jpeg";
}

const BADGE_PDF_IMAGE_FETCH_TIMEOUT_MS = 2_500;
const BADGE_PDF_MAX_IMAGE_BYTES = 2_500_000;

const parseBadgePdfDataUrl = (imageUrl: string): BadgePdfImageAsset | null => {
  const match = /^data:(image\/(?:png|jpeg|jpg));base64,([A-Za-z0-9+/=\s]+)$/i.exec(
    imageUrl.trim(),
  );

  if (match === null) {
    return null;
  }

  const mimeType = match[1]?.toLowerCase();
  const base64Payload = match[2]?.replaceAll(/\s+/g, "");

  if (base64Payload === undefined || base64Payload.length === 0) {
    return null;
  }

  try {
    const binary = atob(base64Payload);

    if (binary.length === 0 || binary.length > BADGE_PDF_MAX_IMAGE_BYTES) {
      return null;
    }

    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));

    if (mimeType === "image/png") {
      return {
        bytes,
        mimeType: "image/png",
      };
    }

    return {
      bytes,
      mimeType: "image/jpeg",
    };
  } catch {
    return null;
  }
};

const inferBadgePdfImageMimeType = (
  imageUrl: URL,
  contentTypeHeader: string | null,
): BadgePdfImageAsset["mimeType"] | null => {
  const contentType = contentTypeHeader?.split(";")[0]?.trim().toLowerCase() ?? null;

  if (contentType === "image/png") {
    return "image/png";
  }

  if (contentType === "image/jpeg" || contentType === "image/jpg") {
    return "image/jpeg";
  }

  const pathname = imageUrl.pathname.toLowerCase();

  if (pathname.endsWith(".png")) {
    return "image/png";
  }

  if (pathname.endsWith(".jpg") || pathname.endsWith(".jpeg")) {
    return "image/jpeg";
  }

  return null;
};

const loadBadgePdfImageAsset = async (imageUrl: string): Promise<BadgePdfImageAsset | null> => {
  const dataUrlAsset = parseBadgePdfDataUrl(imageUrl);

  if (dataUrlAsset !== null) {
    return dataUrlAsset;
  }

  let parsedUrl: URL;

  try {
    parsedUrl = new URL(imageUrl);
  } catch {
    return null;
  }

  if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
    return null;
  }

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, BADGE_PDF_IMAGE_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(parsedUrl.toString(), {
      method: "GET",
      headers: withCredTrailUserAgent({
        Accept: "image/png,image/jpeg,image/*;q=0.8,*/*;q=0.5",
      }),
      signal: abortController.signal,
    });

    if (!response.ok) {
      return null;
    }

    const mimeType = inferBadgePdfImageMimeType(parsedUrl, response.headers.get("content-type"));

    if (mimeType === null) {
      return null;
    }

    const imageBuffer = await response.arrayBuffer();

    if (imageBuffer.byteLength === 0 || imageBuffer.byteLength > BADGE_PDF_MAX_IMAGE_BYTES) {
      return null;
    }

    return {
      bytes: new Uint8Array(imageBuffer),
      mimeType,
    };
  } catch {
    return null;
  } finally {
    clearTimeout(timeoutId);
  }
};

const splitPdfWordToWidth = (
  word: string,
  font: PDFFont,
  fontSize: number,
  maxWidth: number,
): string[] => {
  const chunks: string[] = [];
  let currentChunk = "";

  for (const character of word) {
    const candidate = `${currentChunk}${character}`;

    if (currentChunk.length > 0 && font.widthOfTextAtSize(candidate, fontSize) > maxWidth) {
      chunks.push(currentChunk);
      currentChunk = character;
      continue;
    }

    currentChunk = candidate;
  }

  if (currentChunk.length > 0) {
    chunks.push(currentChunk);
  }

  return chunks.length === 0 ? [word] : chunks;
};

const wrapPdfText = (
  value: string,
  font: PDFFont,
  fontSize: number,
  maxWidth: number,
): string[] => {
  const trimmedValue = value.trim();

  if (trimmedValue.length === 0) {
    return [""];
  }

  const paragraphs = trimmedValue.split(/\r?\n/);
  const lines: string[] = [];

  for (const paragraph of paragraphs) {
    const words = paragraph.split(/\s+/).filter((word) => word.length > 0);

    if (words.length === 0) {
      if (lines.length > 0 && lines.at(-1) !== "") {
        lines.push("");
      }
      continue;
    }

    let currentLine = "";

    for (const word of words) {
      if (font.widthOfTextAtSize(word, fontSize) > maxWidth) {
        if (currentLine.length > 0) {
          lines.push(currentLine);
          currentLine = "";
        }

        const chunks = splitPdfWordToWidth(word, font, fontSize, maxWidth);
        const trailingChunk = chunks.pop();
        lines.push(...chunks);
        currentLine = trailingChunk ?? "";
        continue;
      }

      const candidate = currentLine.length === 0 ? word : `${currentLine} ${word}`;

      if (font.widthOfTextAtSize(candidate, fontSize) <= maxWidth) {
        currentLine = candidate;
        continue;
      }

      lines.push(currentLine);
      currentLine = word;
    }

    if (currentLine.length > 0) {
      lines.push(currentLine);
    }
  }

  return lines.length === 0 ? [""] : lines;
};

const embedBadgePdfImage = async (
  pdfDocument: PDFDocument,
  asset: BadgePdfImageAsset,
): Promise<PDFImage | null> => {
  try {
    if (asset.mimeType === "image/png") {
      return await pdfDocument.embedPng(asset.bytes);
    }

    return await pdfDocument.embedJpg(asset.bytes);
  } catch {
    return null;
  }
};

const drawBadgePdfPlaceholder = (
  page: PDFPage,
  badgeName: string,
  frame: {
    x: number;
    y: number;
    width: number;
    height: number;
  },
): void => {
  const initials = badgeInitialsFromName(badgeName);

  page.drawRectangle({
    x: frame.x,
    y: frame.y,
    width: frame.width,
    height: frame.height,
    color: rgb(0.09, 0.31, 0.18),
  });
  page.drawCircle({
    x: frame.x + frame.width - 36,
    y: frame.y + frame.height - 34,
    size: 24,
    color: rgb(0.96, 0.76, 0.14),
    opacity: 0.28,
  });
  page.drawCircle({
    x: frame.x + 34,
    y: frame.y + 34,
    size: 30,
    color: rgb(0.96, 0.76, 0.14),
    opacity: 0.2,
  });
  page.drawText(initials, {
    x: frame.x + frame.width / 2 - 26,
    y: frame.y + frame.height / 2 - 14,
    size: 28,
    color: rgb(0.96, 0.98, 1),
  });
};

const drawPdfTextLines = (
  page: PDFPage,
  lines: readonly string[],
  x: number,
  startY: number,
  options: {
    font: PDFFont;
    size: number;
    color: ReturnType<typeof rgb>;
    lineHeight: number;
  },
): number => {
  let currentY = startY;

  for (const line of lines) {
    page.drawText(line, {
      x,
      y: currentY,
      font: options.font,
      size: options.size,
      color: options.color,
    });
    currentY -= options.lineHeight;
  }

  return currentY;
};

const drawPdfField = (
  page: PDFPage,
  label: string,
  value: string,
  x: number,
  startY: number,
  options: {
    labelFont: PDFFont;
    labelSize: number;
    labelColor: ReturnType<typeof rgb>;
    valueFont: PDFFont;
    valueSize: number;
    valueColor: ReturnType<typeof rgb>;
    lineHeight: number;
    maxWidth: number;
    gapAfter: number;
    labelGap?: number;
  },
): number => {
  page.drawText(label, {
    x,
    y: startY,
    font: options.labelFont,
    size: options.labelSize,
    color: options.labelColor,
  });

  const wrappedValueLines = wrapPdfText(
    value,
    options.valueFont,
    options.valueSize,
    options.maxWidth,
  );
  const nextY = drawPdfTextLines(page, wrappedValueLines, x, startY - (options.labelGap ?? 13), {
    font: options.valueFont,
    size: options.valueSize,
    color: options.valueColor,
    lineHeight: options.lineHeight,
  });

  return nextY - options.gapAfter;
};

const drawPdfLinkBlock = (
  page: PDFPage,
  label: string,
  value: string,
  x: number,
  startY: number,
  options: {
    labelFont: PDFFont;
    valueFont: PDFFont;
    labelColor: ReturnType<typeof rgb>;
    valueColor: ReturnType<typeof rgb>;
    maxWidth: number;
  },
): number => {
  return drawPdfField(page, label, value, x, startY, {
    labelFont: options.labelFont,
    labelSize: 9.2,
    labelColor: options.labelColor,
    valueFont: options.valueFont,
    valueSize: 9.6,
    valueColor: options.valueColor,
    lineHeight: 11.4,
    maxWidth: options.maxWidth,
    gapAfter: 7,
    labelGap: 11,
  });
};

const drawPdfPanel = (
  page: PDFPage,
  frame: {
    x: number;
    y: number;
    width: number;
    height: number;
  },
  options: {
    fill: ReturnType<typeof rgb>;
    border: ReturnType<typeof rgb>;
    accent?: ReturnType<typeof rgb>;
  },
): void => {
  page.drawRectangle({
    x: frame.x,
    y: frame.y,
    width: frame.width,
    height: frame.height,
    borderWidth: 1,
    borderColor: options.border,
    color: options.fill,
  });

  if (options.accent !== undefined) {
    page.drawRectangle({
      x: frame.x,
      y: frame.y + frame.height - 4,
      width: frame.width,
      height: 4,
      color: options.accent,
    });
  }
};

const drawPdfStatusPill = (
  page: PDFPage,
  text: string,
  x: number,
  y: number,
  options: {
    font: PDFFont;
    size: number;
    fill: ReturnType<typeof rgb>;
    textColor: ReturnType<typeof rgb>;
  },
): number => {
  const horizontalPadding = 12;
  const height = 26;
  const width = options.font.widthOfTextAtSize(text, options.size) + horizontalPadding * 2;

  page.drawRectangle({
    x,
    y,
    width,
    height,
    color: options.fill,
  });

  const textWidth = options.font.widthOfTextAtSize(text, options.size);
  page.drawText(text, {
    x: x + (width - textWidth) / 2,
    y: y + 8.2,
    font: options.font,
    size: options.size,
    color: options.textColor,
  });

  return width;
};

const drawPdfCenteredText = (
  page: PDFPage,
  value: string,
  centerX: number,
  y: number,
  options: {
    font: PDFFont;
    size: number;
    color: ReturnType<typeof rgb>;
  },
): void => {
  const textWidth = options.font.widthOfTextAtSize(value, options.size);

  page.drawText(value, {
    x: centerX - textWidth / 2,
    y,
    font: options.font,
    size: options.size,
    color: options.color,
  });
};

const drawPdfQrCode = (
  page: PDFPage,
  payload: string,
  frame: {
    x: number;
    y: number;
    size: number;
  },
  options: {
    fill: ReturnType<typeof rgb>;
    border: ReturnType<typeof rgb>;
    moduleColor: ReturnType<typeof rgb>;
  },
): void => {
  const qr = createQrCodeMatrix(payload);

  page.drawRectangle({
    x: frame.x,
    y: frame.y,
    width: frame.size,
    height: frame.size,
    color: options.fill,
    borderWidth: 1,
    borderColor: options.border,
  });

  const moduleCount = qr.moduleCount;
  const padding = 5;
  const moduleSize = (frame.size - padding * 2) / moduleCount;

  for (let row = 0; row < moduleCount; row += 1) {
    for (let column = 0; column < moduleCount; column += 1) {
      if (qr.modules[row]?.[column] !== true) {
        continue;
      }

      page.drawRectangle({
        x: frame.x + padding + column * moduleSize,
        y: frame.y + padding + (moduleCount - row - 1) * moduleSize,
        width: moduleSize,
        height: moduleSize,
        color: options.moduleColor,
      });
    }
  }
};

export const renderBadgePdfDocument = async (input: BadgePdfDocumentInput): Promise<Uint8Array> => {
  const pdfDocument = await PDFDocument.create();
  const page = pdfDocument.addPage([612, 792]);
  const regularFont = await pdfDocument.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDocument.embedFont(StandardFonts.HelveticaBold);
  const displayFont = await pdfDocument.embedFont(StandardFonts.TimesRomanBold);

  const pageWidth = page.getWidth();
  const pageHeight = page.getHeight();
  const shellMargin = 24;
  const contentMargin = 34;

  const colors = {
    paper: rgb(0.95, 0.97, 0.99),
    shell: rgb(0.99, 0.995, 1),
    ink: rgb(0.09, 0.14, 0.22),
    muted: rgb(0.33, 0.41, 0.51),
    subtle: rgb(0.44, 0.5, 0.58),
    border: rgb(0.8, 0.84, 0.89),
    borderStrong: rgb(0.71, 0.77, 0.84),
    hero: rgb(0.05, 0.17, 0.31),
    heroOverlay: rgb(0.11, 0.45, 0.72),
    accent: rgb(0.94, 0.74, 0.2),
    panel: rgb(1, 1, 1),
    panelTint: rgb(0.97, 0.985, 1),
    noteTint: rgb(0.995, 0.992, 0.975),
  };

  const normalizedStatus = input.status.toLowerCase();
  const statusPalette =
    normalizedStatus === "revoked"
      ? {
          fill: rgb(0.69, 0.22, 0.17),
          text: rgb(0.99, 0.985, 0.98),
        }
      : normalizedStatus === "suspended"
        ? {
            fill: rgb(0.73, 0.48, 0.14),
            text: rgb(0.99, 0.985, 0.96),
          }
        : normalizedStatus === "expired"
          ? {
              fill: rgb(0.36, 0.43, 0.53),
              text: rgb(0.98, 0.99, 1),
            }
          : {
              fill: rgb(0.11, 0.42, 0.29),
              text: rgb(0.98, 0.99, 1),
            };

  page.drawRectangle({
    x: 0,
    y: 0,
    width: pageWidth,
    height: pageHeight,
    color: colors.paper,
  });
  page.drawRectangle({
    x: shellMargin,
    y: shellMargin,
    width: pageWidth - shellMargin * 2,
    height: pageHeight - shellMargin * 2,
    borderWidth: 1,
    borderColor: colors.border,
    color: colors.shell,
  });

  const headerFrame = {
    x: contentMargin,
    y: 644,
    width: pageWidth - contentMargin * 2,
    height: 104,
  };

  page.drawRectangle({
    x: headerFrame.x,
    y: headerFrame.y,
    width: headerFrame.width,
    height: headerFrame.height,
    color: colors.hero,
  });
  page.drawRectangle({
    x: headerFrame.x + headerFrame.width * 0.58,
    y: headerFrame.y,
    width: headerFrame.width * 0.42,
    height: headerFrame.height,
    color: colors.heroOverlay,
    opacity: 0.38,
  });
  page.drawRectangle({
    x: headerFrame.x + 14,
    y: headerFrame.y + 16,
    width: 6,
    height: headerFrame.height - 32,
    color: colors.accent,
  });
  page.drawText("OPEN BADGES 3.0", {
    x: headerFrame.x + 30,
    y: headerFrame.y + 76,
    size: 9.5,
    color: rgb(0.89, 0.95, 1),
    font: boldFont,
  });
  page.drawText("Learner Badge Record", {
    x: headerFrame.x + 30,
    y: headerFrame.y + 48,
    size: 24,
    color: rgb(0.98, 0.99, 1),
    font: boldFont,
  });
  page.drawText("Recipient copy for professional review, sharing, and formal verification.", {
    x: headerFrame.x + 30,
    y: headerFrame.y + 22,
    size: 10.5,
    color: rgb(0.84, 0.91, 0.98),
    font: regularFont,
  });

  const statusText = input.status.toUpperCase();
  const statusWidth = boldFont.widthOfTextAtSize(statusText, 10.3) + 24;
  drawPdfStatusPill(
    page,
    statusText,
    headerFrame.x + headerFrame.width - statusWidth - 18,
    headerFrame.y + 66,
    {
      font: boldFont,
      size: 10.3,
      fill: statusPalette.fill,
      textColor: statusPalette.text,
    },
  );

  const heroFrame = {
    x: contentMargin,
    y: 424,
    width: pageWidth - contentMargin * 2,
    height: 196,
  };
  drawPdfPanel(page, heroFrame, {
    fill: colors.panel,
    border: colors.border,
    accent: rgb(0.2, 0.46, 0.74),
  });

  const imageFrame = {
    x: heroFrame.x + 18,
    y: heroFrame.y + 24,
    width: 152,
    height: 148,
  };
  drawPdfPanel(page, imageFrame, {
    fill: colors.panelTint,
    border: colors.border,
  });

  let embeddedBadgeImage: PDFImage | null = null;

  if (input.badgeImageUrl !== null) {
    const imageAsset = await loadBadgePdfImageAsset(input.badgeImageUrl);
    embeddedBadgeImage =
      imageAsset === null ? null : await embedBadgePdfImage(pdfDocument, imageAsset);
  }

  if (embeddedBadgeImage === null) {
    drawBadgePdfPlaceholder(page, input.badgeName, imageFrame);
  } else {
    const imageScale = Math.min(
      (imageFrame.width - 20) / embeddedBadgeImage.width,
      (imageFrame.height - 20) / embeddedBadgeImage.height,
    );
    const imageWidth = embeddedBadgeImage.width * imageScale;
    const imageHeight = embeddedBadgeImage.height * imageScale;

    page.drawImage(embeddedBadgeImage, {
      x: imageFrame.x + (imageFrame.width - imageWidth) / 2,
      y: imageFrame.y + (imageFrame.height - imageHeight) / 2,
      width: imageWidth,
      height: imageHeight,
    });
  }

  page.drawText("Badge", {
    x: imageFrame.x + 10,
    y: imageFrame.y + imageFrame.height - 16,
    size: 9,
    color: colors.subtle,
    font: boldFont,
  });

  const detailX = imageFrame.x + imageFrame.width + 22;
  const detailWidth = heroFrame.x + heroFrame.width - detailX - 20;

  page.drawText("Awarded badge", {
    x: detailX,
    y: heroFrame.y + heroFrame.height - 28,
    size: 9.2,
    color: colors.subtle,
    font: boldFont,
  });

  const badgeNameLines = wrapPdfText(input.badgeName, displayFont, 24, detailWidth);
  let detailY = drawPdfTextLines(
    page,
    badgeNameLines,
    detailX,
    heroFrame.y + heroFrame.height - 56,
    {
      font: displayFont,
      size: 24,
      color: colors.ink,
      lineHeight: 26,
    },
  );

  detailY -= 8;
  page.drawText("Awarded to", {
    x: detailX,
    y: detailY,
    size: 9.4,
    color: colors.subtle,
    font: boldFont,
  });
  detailY = drawPdfTextLines(
    page,
    wrapPdfText(input.recipientName, boldFont, 18, detailWidth),
    detailX,
    detailY - 21,
    {
      font: boldFont,
      size: 18,
      color: colors.ink,
      lineHeight: 20,
    },
  );

  const metaStartY = detailY - 4;
  const metaColumnWidth = (detailWidth - 18) / 2;
  drawPdfField(page, "Issued by", input.issuerName, detailX, metaStartY, {
    labelFont: boldFont,
    labelSize: 9.2,
    labelColor: colors.subtle,
    valueFont: boldFont,
    valueSize: 11.8,
    valueColor: colors.ink,
    lineHeight: 13.2,
    maxWidth: metaColumnWidth,
    gapAfter: 0,
    labelGap: 12,
  });
  drawPdfField(page, "Issued on", input.issuedAt, detailX + metaColumnWidth + 18, metaStartY, {
    labelFont: boldFont,
    labelSize: 9.2,
    labelColor: colors.subtle,
    valueFont: regularFont,
    valueSize: 11.2,
    valueColor: colors.ink,
    lineHeight: 13,
    maxWidth: metaColumnWidth,
    gapAfter: 0,
    labelGap: 12,
  });

  const lowerPanelY = 184;
  const lowerPanelHeight = 224;
  const lowerPanelGap = 16;
  const lowerPanelWidth = (heroFrame.width - lowerPanelGap) / 2;
  const verificationFrame = {
    x: contentMargin,
    y: lowerPanelY,
    width: lowerPanelWidth,
    height: lowerPanelHeight,
  };
  const recordFrame = {
    x: contentMargin + lowerPanelWidth + lowerPanelGap,
    y: lowerPanelY,
    width: lowerPanelWidth,
    height: lowerPanelHeight,
  };

  drawPdfPanel(page, verificationFrame, {
    fill: colors.panel,
    border: colors.border,
    accent: rgb(0.16, 0.44, 0.71),
  });
  drawPdfPanel(page, recordFrame, {
    fill: colors.panel,
    border: colors.border,
    accent: statusPalette.fill,
  });

  page.drawText("Verification references", {
    x: verificationFrame.x + 18,
    y: verificationFrame.y + verificationFrame.height - 26,
    size: 13,
    color: colors.ink,
    font: boldFont,
  });
  drawPdfTextLines(
    page,
    wrapPdfText(
      "Share the public badge page for reviewers and use the JSON endpoints for direct checks.",
      regularFont,
      9.6,
      verificationFrame.width - 36,
    ),
    verificationFrame.x + 18,
    verificationFrame.y + verificationFrame.height - 44,
    {
      font: regularFont,
      size: 9.6,
      color: colors.muted,
      lineHeight: 11.2,
    },
  );

  let verificationY = verificationFrame.y + verificationFrame.height - 78;
  const verificationContentX = verificationFrame.x + 18;
  const verificationContentWidth = verificationFrame.width - 36;
  verificationY = drawPdfLinkBlock(
    page,
    "Public badge page",
    input.publicBadgeUrl,
    verificationContentX,
    verificationY,
    {
      labelFont: boldFont,
      valueFont: regularFont,
      labelColor: colors.subtle,
      valueColor: colors.ink,
      maxWidth: verificationContentWidth,
    },
  );
  verificationY -= 5;
  verificationY = drawPdfLinkBlock(
    page,
    "Verification endpoint",
    input.verificationUrl,
    verificationContentX,
    verificationY,
    {
      labelFont: boldFont,
      valueFont: regularFont,
      labelColor: colors.subtle,
      valueColor: colors.ink,
      maxWidth: verificationContentWidth,
    },
  );
  verificationY -= 5;
  drawPdfLinkBlock(
    page,
    "Open Badges JSON-LD",
    input.ob3JsonUrl,
    verificationContentX,
    verificationY,
    {
      labelFont: boldFont,
      valueFont: regularFont,
      labelColor: colors.subtle,
      valueColor: colors.ink,
      maxWidth: verificationContentWidth,
    },
  );

  page.drawText("Record details", {
    x: recordFrame.x + 18,
    y: recordFrame.y + recordFrame.height - 26,
    size: 13,
    color: colors.ink,
    font: boldFont,
  });
  drawPdfTextLines(
    page,
    wrapPdfText(
      "Technical identifiers from the signed credential and assertion record.",
      regularFont,
      9.6,
      recordFrame.width - 36,
    ),
    recordFrame.x + 18,
    recordFrame.y + recordFrame.height - 44,
    {
      font: regularFont,
      size: 9.6,
      color: colors.muted,
      lineHeight: 11.2,
    },
  );

  let recordY = recordFrame.y + recordFrame.height - 78;
  const recordContentX = recordFrame.x + 18;
  const recordContentWidth = recordFrame.width - 36;
  recordY = drawPdfField(page, "Credential status", input.status, recordContentX, recordY, {
    labelFont: boldFont,
    labelSize: 9.2,
    labelColor: colors.subtle,
    valueFont: boldFont,
    valueSize: 11.4,
    valueColor: colors.ink,
    lineHeight: 13,
    maxWidth: recordContentWidth,
    gapAfter: 8,
    labelGap: 12,
  });
  recordY = drawPdfField(
    page,
    "Recipient identifier",
    input.recipientIdentifier,
    recordContentX,
    recordY,
    {
      labelFont: boldFont,
      labelSize: 9.2,
      labelColor: colors.subtle,
      valueFont: regularFont,
      valueSize: 9.6,
      valueColor: colors.ink,
      lineHeight: 11.2,
      maxWidth: recordContentWidth,
      gapAfter: 7,
      labelGap: 11,
    },
  );
  recordY = drawPdfField(page, "Assertion ID", input.assertionId, recordContentX, recordY, {
    labelFont: boldFont,
    labelSize: 9.2,
    labelColor: colors.subtle,
    valueFont: regularFont,
    valueSize: 9.6,
    valueColor: colors.ink,
    lineHeight: 11.2,
    maxWidth: recordContentWidth,
    gapAfter: 7,
    labelGap: 11,
  });
  recordY = drawPdfField(page, "Credential ID", input.credentialId, recordContentX, recordY, {
    labelFont: boldFont,
    labelSize: 9.2,
    labelColor: colors.subtle,
    valueFont: regularFont,
    valueSize: 9.6,
    valueColor: colors.ink,
    lineHeight: 11.2,
    maxWidth: recordContentWidth,
    gapAfter: 7,
    labelGap: 11,
  });

  if (input.revokedAt !== undefined) {
    drawPdfField(page, "Revoked at", input.revokedAt, recordContentX, recordY, {
      labelFont: boldFont,
      labelSize: 9.2,
      labelColor: colors.subtle,
      valueFont: regularFont,
      valueSize: 9.6,
      valueColor: colors.ink,
      lineHeight: 11.2,
      maxWidth: recordContentWidth,
      gapAfter: 0,
      labelGap: 11,
    });
  }

  const noteFrame = {
    x: contentMargin,
    y: 86,
    width: pageWidth - contentMargin * 2,
    height: 82,
  };
  drawPdfPanel(page, noteFrame, {
    fill: colors.noteTint,
    border: colors.border,
  });
  page.drawRectangle({
    x: noteFrame.x,
    y: noteFrame.y,
    width: 6,
    height: noteFrame.height,
    color: colors.accent,
  });
  page.drawText("How to use this copy", {
    x: noteFrame.x + 18,
    y: noteFrame.y + noteFrame.height - 22,
    size: 11.2,
    color: colors.ink,
    font: boldFont,
  });

  const qrFrame = {
    x: noteFrame.x + noteFrame.width - 76,
    y: noteFrame.y + 12,
    size: 52,
  };
  const qrLabel = "Scan to verify online";
  page.drawText(qrLabel, {
    x: qrFrame.x + (qrFrame.size - boldFont.widthOfTextAtSize(qrLabel, 6.8)) / 2,
    y: qrFrame.y + qrFrame.size + 5,
    size: 6.8,
    color: colors.subtle,
    font: boldFont,
  });
  drawPdfQrCode(page, input.publicBadgeUrl, qrFrame, {
    fill: colors.panel,
    border: colors.borderStrong,
    moduleColor: colors.ink,
  });

  drawPdfTextLines(
    page,
    wrapPdfText(
      input.revokedAt === undefined
        ? "For a quick review, open the public badge page. For an automated check, use the verification endpoint or the JSON-LD link above."
        : "This credential has changed lifecycle state. Confirm the current status with the public badge page or the verification endpoint above before relying on this copy.",
      regularFont,
      10.2,
      qrFrame.x - noteFrame.x - 36,
    ),
    noteFrame.x + 18,
    noteFrame.y + 32,
    {
      font: regularFont,
      size: 10.2,
      color: colors.muted,
      lineHeight: 12.2,
    },
  );

  drawPdfCenteredText(
    page,
    "Recipient copy • Generated from the authoritative Open Badges 3.0 credential record",
    pageWidth / 2,
    70,
    {
      font: regularFont,
      size: 9.2,
      color: colors.subtle,
    },
  );
  drawPdfCenteredText(page, input.publicBadgeUrl, pageWidth / 2, 54, {
    font: regularFont,
    size: 8.9,
    color: colors.muted,
  });

  const pdfBytes = await pdfDocument.save();
  return Uint8Array.from(pdfBytes);
};
