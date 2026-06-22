import qrcode from "qrcode-generator";

const QR_ERROR_CORRECTION_LEVEL = "M";

export interface QrCodeMatrix {
  moduleCount: number;
  modules: readonly (readonly boolean[])[];
}

const buildQrCode = (payload: string) => {
  const qr = qrcode(0, QR_ERROR_CORRECTION_LEVEL);
  qr.addData(payload);
  qr.make();

  return qr;
};

export const createQrCodeMatrix = (payload: string): QrCodeMatrix => {
  const qr = buildQrCode(payload);
  const moduleCount = qr.getModuleCount();
  const modules: boolean[][] = [];

  for (let row = 0; row < moduleCount; row += 1) {
    const moduleRow: boolean[] = [];

    for (let column = 0; column < moduleCount; column += 1) {
      moduleRow.push(qr.isDark(row, column));
    }

    modules.push(moduleRow);
  }

  return {
    moduleCount,
    modules,
  };
};

export const renderQrCodeSvg = (payload: string): string => {
  return buildQrCode(payload).createSvgTag({
    cellSize: 4,
    margin: 0,
    scalable: true,
  });
};
