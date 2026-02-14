import { PDFDocument, StandardFonts, rgb, type PDFImage, type PDFPage } from 'pdf-lib';

export const badgeInitialsFromName = (badgeName: string): string => {
  const trimmedName = badgeName.trim();

  if (trimmedName.length === 0) {
    return 'BD';
  }

  const words = trimmedName.split(/\s+/).filter((word) => word.length > 0);
  const firstWord = words.at(0);

  if (firstWord === undefined) {
    return 'BD';
  }

  const secondWord = words.at(1);
  const firstInitial = firstWord.slice(0, 1);
  const secondInitial = secondWord === undefined ? firstWord.slice(1, 2) : secondWord.slice(0, 1);
  const initials = `${firstInitial}${secondInitial}`.replaceAll(/[^a-zA-Z0-9]/g, '').toUpperCase();

  return initials.length === 0 ? 'BD' : initials;
};

export const credentialDownloadFilename = (assertionId: string): string => {
  const safeAssertionId = assertionId.replaceAll(/[^a-zA-Z0-9_-]+/g, '-').replaceAll(/-+/g, '-');
  const trimmed = safeAssertionId.replaceAll(/^-|-$/g, '');
  const fallback = trimmed.length === 0 ? 'badge' : trimmed;

  return `${fallback}.jsonld`;
};

export const credentialPdfDownloadFilename = (assertionId: string): string => {
  const safeAssertionId = assertionId.replaceAll(/[^a-zA-Z0-9_-]+/g, '-').replaceAll(/-+/g, '-');
  const trimmed = safeAssertionId.replaceAll(/^-|-$/g, '');
  const fallback = trimmed.length === 0 ? 'badge' : trimmed;

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
  mimeType: 'image/png' | 'image/jpeg';
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
  const base64Payload = match[2]?.replaceAll(/\s+/g, '');

  if (base64Payload === undefined || base64Payload.length === 0) {
    return null;
  }

  try {
    const binary = atob(base64Payload);

    if (binary.length === 0 || binary.length > BADGE_PDF_MAX_IMAGE_BYTES) {
      return null;
    }

    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));

    if (mimeType === 'image/png') {
      return {
        bytes,
        mimeType: 'image/png',
      };
    }

    return {
      bytes,
      mimeType: 'image/jpeg',
    };
  } catch {
    return null;
  }
};

const inferBadgePdfImageMimeType = (
  imageUrl: URL,
  contentTypeHeader: string | null,
): BadgePdfImageAsset['mimeType'] | null => {
  const contentType = contentTypeHeader?.split(';')[0]?.trim().toLowerCase() ?? null;

  if (contentType === 'image/png') {
    return 'image/png';
  }

  if (contentType === 'image/jpeg' || contentType === 'image/jpg') {
    return 'image/jpeg';
  }

  const pathname = imageUrl.pathname.toLowerCase();

  if (pathname.endsWith('.png')) {
    return 'image/png';
  }

  if (pathname.endsWith('.jpg') || pathname.endsWith('.jpeg')) {
    return 'image/jpeg';
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

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return null;
  }

  const abortController = new AbortController();
  const timeoutId = setTimeout(() => {
    abortController.abort();
  }, BADGE_PDF_IMAGE_FETCH_TIMEOUT_MS);

  try {
    const response = await fetch(parsedUrl.toString(), {
      method: 'GET',
      headers: {
        Accept: 'image/png,image/jpeg,image/*;q=0.8,*/*;q=0.5',
      },
      signal: abortController.signal,
    });

    if (!response.ok) {
      return null;
    }

    const mimeType = inferBadgePdfImageMimeType(parsedUrl, response.headers.get('content-type'));

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

const wrapPdfText = (value: string, maxChars: number): string[] => {
  if (value.length <= maxChars) {
    return [value];
  }

  const words = value.split(/\s+/).filter((word) => word.length > 0);

  if (words.length === 0) {
    return [value.slice(0, maxChars)];
  }

  const lines: string[] = [];
  let currentLine = '';

  for (const word of words) {
    let remainingWord = word;

    while (remainingWord.length > maxChars) {
      if (currentLine.length > 0) {
        lines.push(currentLine);
        currentLine = '';
      }

      lines.push(remainingWord.slice(0, maxChars));
      remainingWord = remainingWord.slice(maxChars);
    }

    if (remainingWord.length === 0) {
      continue;
    }

    const nextLine = currentLine.length === 0 ? remainingWord : `${currentLine} ${remainingWord}`;
    if (nextLine.length <= maxChars) {
      currentLine = nextLine;
      continue;
    }

    lines.push(currentLine);
    currentLine = remainingWord;
  }

  if (currentLine.length > 0) {
    lines.push(currentLine);
  }

  return lines;
};

const embedBadgePdfImage = async (
  pdfDocument: PDFDocument,
  asset: BadgePdfImageAsset,
): Promise<PDFImage | null> => {
  try {
    if (asset.mimeType === 'image/png') {
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
): number => {
  page.drawText(label, {
    x,
    y: startY,
    size: 10,
    color: rgb(0.36, 0.42, 0.49),
  });
  const wrappedValueLines = wrapPdfText(value, 45);
  const nextY = drawPdfTextLines(page, wrappedValueLines, x, startY - 14, {
    size: 12,
    color: rgb(0.08, 0.11, 0.17),
    lineHeight: 14,
  });

  return nextY - 8;
};

const drawPdfLinkBlock = (
  page: PDFPage,
  label: string,
  value: string,
  x: number,
  startY: number,
): number => {
  page.drawText(label, {
    x,
    y: startY,
    size: 10,
    color: rgb(0.36, 0.42, 0.49),
  });
  const wrappedValueLines = wrapPdfText(value, 88);

  return drawPdfTextLines(page, wrappedValueLines, x, startY - 13, {
    size: 10.5,
    color: rgb(0.08, 0.11, 0.17),
    lineHeight: 13,
  });
};

export const renderBadgePdfDocument = async (input: BadgePdfDocumentInput): Promise<Uint8Array> => {
  const pdfDocument = await PDFDocument.create();
  const page = pdfDocument.addPage([612, 792]);
  const regularFont = await pdfDocument.embedFont(StandardFonts.Helvetica);
  const boldFont = await pdfDocument.embedFont(StandardFonts.HelveticaBold);

  const pageWidth = page.getWidth();
  const pageHeight = page.getHeight();
  const margin = 30;

  page.drawRectangle({
    x: 0,
    y: 0,
    width: pageWidth,
    height: pageHeight,
    color: rgb(0.97, 0.98, 0.99),
  });
  page.drawRectangle({
    x: margin - 6,
    y: margin - 6,
    width: pageWidth - (margin - 6) * 2,
    height: pageHeight - (margin - 6) * 2,
    borderWidth: 1,
    borderColor: rgb(0.76, 0.81, 0.87),
  });

  const headerY = pageHeight - 96;
  page.drawRectangle({
    x: margin,
    y: headerY,
    width: pageWidth - margin * 2,
    height: 58,
    color: rgb(0.09, 0.35, 0.21),
  });
  page.drawRectangle({
    x: margin + 10,
    y: headerY + 8,
    width: 7,
    height: 42,
    color: rgb(0.96, 0.76, 0.14),
  });
  page.drawText('OFFICIAL BADGE CREDENTIAL', {
    x: margin + 26,
    y: headerY + 33,
    size: 18,
    color: rgb(0.97, 0.98, 1),
    font: boldFont,
  });
  page.drawText('Issued by CredTrail - Open Badges 3.0 Verification Record', {
    x: margin + 26,
    y: headerY + 15,
    size: 10.5,
    color: rgb(0.89, 0.95, 0.92),
    font: regularFont,
  });

  const imageFrame = {
    x: margin + 14,
    y: 408,
    width: 212,
    height: 222,
  };
  page.drawRectangle({
    x: imageFrame.x - 1,
    y: imageFrame.y - 1,
    width: imageFrame.width + 2,
    height: imageFrame.height + 2,
    borderWidth: 1,
    borderColor: rgb(0.72, 0.79, 0.86),
    color: rgb(1, 1, 1),
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
      (imageFrame.width - 10) / embeddedBadgeImage.width,
      (imageFrame.height - 10) / embeddedBadgeImage.height,
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

  page.drawText('Badge Artwork', {
    x: imageFrame.x + 4,
    y: imageFrame.y - 16,
    size: 9.5,
    color: rgb(0.36, 0.42, 0.49),
    font: regularFont,
  });

  const statusColor =
    input.status.toLowerCase() === 'revoked' ? rgb(0.66, 0.14, 0.09) : rgb(0.1, 0.41, 0.24);
  page.drawRectangle({
    x: 446,
    y: 618,
    width: 136,
    height: 28,
    color: statusColor,
  });
  page.drawText(input.status.toUpperCase(), {
    x: 474,
    y: 628,
    size: 10.5,
    color: rgb(0.98, 0.99, 1),
    font: boldFont,
  });

  const badgeNameLines = wrapPdfText(input.badgeName, 34);
  let detailY = drawPdfTextLines(page, badgeNameLines, 276, 588, {
    size: 21,
    color: rgb(0.08, 0.11, 0.17),
    lineHeight: 24,
  });
  detailY -= 6;

  detailY = drawPdfField(page, 'Recipient', input.recipientName, 276, detailY);
  detailY = drawPdfField(page, 'Recipient identifier', input.recipientIdentifier, 276, detailY);
  detailY = drawPdfField(page, 'Issuing organization', input.issuerName, 276, detailY);
  detailY = drawPdfField(page, 'Issued at', input.issuedAt, 276, detailY);
  detailY = drawPdfField(page, 'Assertion ID', input.assertionId, 276, detailY);
  detailY = drawPdfField(page, 'Credential ID', input.credentialId, 276, detailY);

  if (input.revokedAt !== undefined) {
    drawPdfField(page, 'Revoked at', input.revokedAt, 276, detailY);
  }

  page.drawLine({
    start: {
      x: margin + 2,
      y: 365,
    },
    end: {
      x: pageWidth - margin - 2,
      y: 365,
    },
    thickness: 1,
    color: rgb(0.79, 0.83, 0.89),
  });

  page.drawText('Verification References', {
    x: margin + 14,
    y: 344,
    size: 14.5,
    color: rgb(0.09, 0.35, 0.21),
    font: boldFont,
  });

  let verificationY = 324;
  verificationY = drawPdfLinkBlock(
    page,
    'Public badge page',
    input.publicBadgeUrl,
    margin + 14,
    verificationY,
  );
  verificationY -= 6;
  verificationY = drawPdfLinkBlock(
    page,
    'Verification JSON endpoint',
    input.verificationUrl,
    margin + 14,
    verificationY,
  );
  verificationY -= 6;
  drawPdfLinkBlock(page, 'Open Badges 3.0 JSON-LD', input.ob3JsonUrl, margin + 14, verificationY);

  page.drawRectangle({
    x: margin + 14,
    y: 90,
    width: pageWidth - (margin + 14) * 2,
    height: 66,
    borderWidth: 1,
    borderColor: rgb(0.8, 0.84, 0.89),
    color: rgb(1, 1, 1),
  });
  page.drawText(
    'This credential record is issued as an official verification document for institutional and hiring workflows.',
    {
      x: margin + 24,
      y: 130,
      size: 10.5,
      color: rgb(0.26, 0.31, 0.38),
      font: regularFont,
    },
  );
  page.drawText('Authenticity can be confirmed using the verification references above.', {
    x: margin + 24,
    y: 114,
    size: 10.5,
    color: rgb(0.26, 0.31, 0.38),
    font: regularFont,
  });

  page.drawLine({
    start: {
      x: margin + 28,
      y: 68,
    },
    end: {
      x: margin + 222,
      y: 68,
    },
    thickness: 1,
    color: rgb(0.64, 0.69, 0.75),
  });
  page.drawLine({
    start: {
      x: pageWidth - margin - 222,
      y: 68,
    },
    end: {
      x: pageWidth - margin - 28,
      y: 68,
    },
    thickness: 1,
    color: rgb(0.64, 0.69, 0.75),
  });
  page.drawText('Issuer signature reference', {
    x: margin + 28,
    y: 55,
    size: 9,
    color: rgb(0.4, 0.46, 0.53),
    font: regularFont,
  });
  page.drawText('Recipient copy', {
    x: pageWidth - margin - 130,
    y: 55,
    size: 9,
    color: rgb(0.4, 0.46, 0.53),
    font: regularFont,
  });

  const pdfBytes = await pdfDocument.save();
  return Uint8Array.from(pdfBytes);
};
