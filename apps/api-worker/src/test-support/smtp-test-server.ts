import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Socket } from "node:net";
import { SMTPServer } from "smtp-server";
import { simpleParser, type ParsedMail } from "mailparser";
import type { EmailEnvironment } from "../runtime/node-email-config";

/** Captured wire delivery from the disposable SMTP relay. */
export interface CapturedSmtpMessage {
  readonly recipients: string[];
  readonly secure: boolean;
  readonly mail: ParsedMail;
}
/** Failures the owned relay can exercise through actual protocol responses. */
export interface SmtpTestOptions {
  readonly mismatchedCertificate?: boolean;
  readonly security?: "tls" | "starttls";
  readonly noStarttls?: boolean;
  readonly rejectAuth?: boolean;
  readonly rejectSender?: boolean;
  readonly rejectRecipients?: readonly string[];
  readonly rejectionCode?: 451 | 550;
  readonly disconnectAfterData?: boolean;
  readonly stallGreeting?: boolean;
  readonly auth?: "none" | "login";
}
/** An owned relay and its disposable trust anchor. */
export interface SmtpTestServer {
  readonly env: EmailEnvironment;
  readonly ca: string;
  readonly messages: CapturedSmtpMessage[];
  close(): Promise<void>;
}

/** Start a TLS relay on an ephemeral loopback port; never forward mail externally. */
export const createSmtpTestServer = async (
  options: SmtpTestOptions = {},
): Promise<SmtpTestServer> => {
  const directory = mkdtempSync(join(tmpdir(), "credtrail-smtp-test-"));
  const keyPath = join(directory, "server.key");
  const certPath = join(directory, "server.crt");
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-days",
      "2",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-subj",
      options.mismatchedCertificate ? "/CN=wrong.example.edu" : "/CN=localhost",
      "-addext",
      options.mismatchedCertificate
        ? "subjectAltName=DNS:wrong.example.edu"
        : "subjectAltName=DNS:localhost",
    ],
    { stdio: "ignore" },
  );
  const ca = readFileSync(certPath, "utf8");
  const messages: CapturedSmtpMessage[] = [];
  const sockets = new Set<Socket>();
  const rejection = (): Error & { responseCode: number } =>
    Object.assign(new Error("Disposable relay rejection"), {
      responseCode: options.rejectionCode ?? 550,
    });
  const server = new SMTPServer({
    secure: options.security === "tls",
    key: readFileSync(keyPath),
    cert: ca,
    disabledCommands: options.noStarttls ? ["STARTTLS"] : [],
    authOptional: options.auth === "none",
    logger: false,
    closeTimeout: 100,
    onConnect: (_session, callback) => {
      if (!options.stallGreeting) callback();
    },
    onAuth: (auth, _session, callback) => {
      if (options.rejectAuth || auth.username !== "disposable" || auth.password !== " secret ")
        callback(new Error("Bad disposable authentication"));
      else callback(null, { user: "disposable" });
    },
    onMailFrom: (_address, _session, callback) =>
      callback(options.rejectSender ? rejection() : null),
    onRcptTo: (address, _session, callback) =>
      callback(options.rejectRecipients?.includes(address.address) ? rejection() : null),
    onData: (stream, session, callback) => {
      void simpleParser(stream)
        .then((mail) => {
          messages.push({
            mail,
            secure: session.secure,
            recipients: session.envelope.rcptTo.map((recipient) => recipient.address),
          });
          if (options.disconnectAfterData) {
            for (const socket of sockets) socket.destroy();
          } else callback(null, "Disposable relay accepted");
        })
        .catch(() => callback(new Error("Disposable MIME parse failed")));
    },
  });
  // Client TLS validation errors are expected cases, not uncaught relay errors.
  server.on("error", () => undefined);
  server.server.on("connection", (socket: Socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.server.address();
    if (address === null || typeof address === "string")
      throw new Error("SMTP test relay did not bind");
    return {
      ca,
      messages,
      env: {
        EMAIL_PROVIDER: "smtp",
        SMTP_HOST: "localhost",
        SMTP_PORT: String(address.port),
        SMTP_SECURITY: options.security ?? "starttls",
        SMTP_AUTH: options.auth ?? "login",
        ...(options.auth === "none"
          ? {}
          : { SMTP_USERNAME: "disposable", SMTP_PASSWORD: " secret " }),
        SMTP_TLS_CA_FILE: certPath,
        TRANSACTIONAL_EMAIL_FROM_ADDRESS: "badges@example.edu",
        TRANSACTIONAL_EMAIL_FROM_NAME: "University Credentials",
        TRANSACTIONAL_EMAIL_REPLY_TO: "support@example.edu",
        ISSUANCE_EMAIL_BCC: "records@example.edu",
      },
      close: async (): Promise<void> => {
        for (const socket of sockets) socket.destroy();
        await new Promise<void>((resolve) => server.close(resolve));
        rmSync(directory, { recursive: true, force: true });
      },
    };
  } catch (cause: unknown) {
    rmSync(directory, { recursive: true, force: true });
    throw cause;
  }
};
