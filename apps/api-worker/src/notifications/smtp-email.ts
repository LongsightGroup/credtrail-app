import nodemailer, {
  type SendMailOptions,
  type Transporter,
  type SentMessageInfo,
} from "nodemailer";
import { z } from "zod";
import { emailMailboxSchema, type SmtpConfig } from "../runtime/node-email-config";

const header = z
  .string()
  .max(998)
  .refine((value) => !/[\r\n]/u.test(value));
const address = z.union([
  emailMailboxSchema,
  z.strictObject({ email: emailMailboxSchema, name: header }),
]);
const messageSchema = z
  .object({
    from: address,
    to: address,
    cc: z.union([address, z.array(address).max(10)]).optional(),
    bcc: z.union([address, z.array(address).max(10)]).optional(),
    replyTo: address.optional(),
    subject: header,
    text: z.string().optional(),
    html: z.string().optional(),
    headers: z.record(header, header).optional(),
    attachments: z.array(z.never()).max(0).optional(),
  })
  .refine((value) => value.text !== undefined || value.html !== undefined);

/** Safe SMTP failure categories, never including server replies or message contents. */
export type SmtpFailureKind =
  | "authentication"
  | "tls"
  | "connection"
  | "timeout"
  | "rejected"
  | "temporary_rejection"
  | "invalid_message"
  | "cancelled";
const summaries: Record<SmtpFailureKind, string> = {
  authentication: "SMTP authentication failed—check the username and password",
  tls: "SMTP TLS failed—check the certificate and TLS mode; STARTTLS must be supported",
  connection:
    "SMTP connection failed—check the host, port, and network; acceptance may be uncertain, so do not resend automatically",
  timeout: "SMTP timed out—relay acceptance may be uncertain; do not resend automatically",
  rejected:
    "SMTP rejected the sender or primary recipient—check the sender authorization and recipient",
  temporary_rejection:
    "SMTP temporarily rejected the message—slow down and check the relay limits or availability",
  invalid_message: "SMTP message is invalid—check the sender, recipient, and message headers",
  cancelled: "SMTP operation was cancelled",
};
/** A sanitized framework-boundary error. */
export class SmtpFailure extends Error {
  constructor(readonly kind: SmtpFailureKind) {
    super(summaries[kind]);
    this.name = "SmtpFailure";
  }
}
/** Typed SMTP operation result inside the exception-based email binding boundary. */
export type SmtpResult<T> =
  | { readonly status: "ok"; readonly value: T }
  | { readonly status: "error"; readonly error: SmtpFailure };
/** SMTP capability with connection verification independent of sending messages. */
export interface SmtpEmail {
  readonly binding: SendEmail;
  verify(): Promise<SmtpResult<void>>;
}

const errorSchema = z.object({
  code: z.string().optional(),
  message: z.string().optional(),
  responseCode: z.number().int().optional(),
});
const classify = (cause: unknown): SmtpFailure => {
  const error = errorSchema.safeParse(cause);
  const code = error.success ? error.data.code : undefined;
  if (
    error.success &&
    error.data.responseCode !== undefined &&
    error.data.responseCode >= 400 &&
    error.data.responseCode < 500
  )
    return new SmtpFailure("temporary_rejection");
  if (code === "EAUTH") return new SmtpFailure("authentication");
  if (code === "ETIMEDOUT") return new SmtpFailure("timeout");
  if (code === "ABORT_ERR") return new SmtpFailure("cancelled");
  if (
    code === "ETLS" ||
    code?.startsWith("ERR_TLS") ||
    code?.includes("CERT") ||
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    (code === "ESOCKET" &&
      error.success &&
      /certificate|self.signed|hostname|altname/iu.test(error.data.message ?? ""))
  )
    return new SmtpFailure("tls");
  if (code === "EENVELOPE" || code === "EMESSAGE") return new SmtpFailure("rejected");
  return new SmtpFailure("connection");
};
const mailAddress = (value: z.infer<typeof address>): string | { name: string; address: string } =>
  typeof value === "string" ? value : { name: value.name, address: value.email };
const mailAddresses = (
  value: z.infer<typeof address> | z.infer<typeof address>[] | undefined,
): SendMailOptions["bcc"] =>
  value === undefined
    ? undefined
    : Array.isArray(value)
      ? value.map(mailAddress)
      : mailAddress(value);
const resultSchema = z.object({
  messageId: z.string(),
  accepted: z.array(z.union([z.string(), z.object({ address: z.string() })])),
  rejected: z.array(z.unknown()),
  rejectedErrors: z
    .array(z.object({ recipient: z.string(), responseCode: z.number().int().optional() }))
    .optional(),
});

/** Construct a Node-only SMTP binding with required TLS and bounded connection lifetimes. */
export const createSmtpEmail = (config: SmtpConfig): SmtpEmail => {
  const transport: Transporter<SentMessageInfo> = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.security === "tls",
    requireTLS: config.security === "starttls",
    auth:
      config.auth.kind === "none"
        ? undefined
        : { user: config.auth.username, pass: config.auth.password.reveal() },
    tls: {
      rejectUnauthorized: true,
      minVersion: "TLSv1.2",
      servername: config.host,
      ...(config.ca === undefined ? {} : { ca: config.ca }),
    },
    pool: false,
    disableFileAccess: true,
    disableUrlAccess: true,
    logger: false,
    debug: false,
    dnsTimeout: 10_000,
    connectionTimeout: 10_000,
    greetingTimeout: 10_000,
    socketTimeout: 30_000,
  });
  const send = async (input: unknown): Promise<SmtpResult<EmailSendResult>> => {
    const parsed = messageSchema.safeParse(input);
    if (!parsed.success) return { status: "error", error: new SmtpFailure("invalid_message") };
    const message = parsed.data;
    try {
      const received: unknown = await transport.sendMail({
        from: mailAddress(message.from),
        to: mailAddress(message.to),
        cc: mailAddresses(message.cc),
        bcc: mailAddresses(message.bcc),
        replyTo: message.replyTo === undefined ? undefined : mailAddress(message.replyTo),
        subject: message.subject,
        text: message.text,
        html: message.html,
        headers: message.headers,
      });
      const result = resultSchema.safeParse(received);
      if (!result.success) return { status: "error", error: new SmtpFailure("connection") };
      const primary = typeof message.to === "string" ? message.to : message.to.email;
      if (
        !result.data.accepted.some(
          (item) => (typeof item === "string" ? item : item.address) === primary,
        )
      ) {
        const rejection = result.data.rejectedErrors?.find((error) => error.recipient === primary);
        const code = rejection?.responseCode;
        return {
          status: "error",
          error: new SmtpFailure(
            code !== undefined && code >= 400 && code < 500 ? "temporary_rejection" : "rejected",
          ),
        };
      }
      if (result.data.rejected.length > 0)
        console.warn(
          JSON.stringify({
            message: "smtp_optional_recipient_rejected",
            count: result.data.rejected.length,
          }),
        );
      return { status: "ok", value: { messageId: result.data.messageId } };
    } catch (cause: unknown) {
      return { status: "error", error: classify(cause) };
    }
  };
  return {
    binding: {
      send: async (message): Promise<EmailSendResult> => {
        const result = await send(message);
        if (result.status === "error") throw result.error;
        return result.value;
      },
    },
    verify: async (): Promise<SmtpResult<void>> => {
      try {
        await transport.verify();
        return { status: "ok", value: undefined };
      } catch (cause: unknown) {
        return { status: "error", error: classify(cause) };
      }
    },
  };
};
