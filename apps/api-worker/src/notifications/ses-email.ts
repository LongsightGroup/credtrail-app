import {
  SESv2Client,
  SendEmailCommand,
  type SendEmailCommandInput,
  type SendEmailCommandOutput,
} from "@aws-sdk/client-sesv2";

type SendEmailBuilderInput = Parameters<SendEmail["send"]>[0] extends EmailMessage
  ? never
  : Parameters<SendEmail["send"]>[0];

interface SesClientLike {
  send(command: SendEmailCommand): Promise<SendEmailCommandOutput>;
}

export interface CreateSesEmailBindingInput {
  region: string;
  configurationSetName?: string | undefined;
}

const escapeDisplayName = (name: string): string => {
  return name.replace(/["\\]/g, (match) => {
    return `\\${match}`;
  });
};

const formatEmailAddress = (address: string | EmailAddress): string => {
  if (typeof address === "string") {
    return address;
  }

  const email = address.email.trim();
  const name = address.name.trim();

  if (name.length === 0) {
    return email;
  }

  return `"${escapeDisplayName(name)}" <${email}>`;
};

const addressList = (
  input: string | EmailAddress | (string | EmailAddress)[] | undefined,
): string[] | undefined => {
  if (input === undefined) {
    return undefined;
  }

  const values = Array.isArray(input) ? input : [input];
  const normalized = values
    .map((value) => formatEmailAddress(value).trim())
    .filter((value) => value.length > 0);
  return normalized.length === 0 ? undefined : normalized;
};

export const buildSesSendEmailInput = (
  message: SendEmailBuilderInput,
  options?: {
    configurationSetName?: string | undefined;
  },
): SendEmailCommandInput => {
  if (message.attachments !== undefined && message.attachments.length > 0) {
    throw new Error("SES transactional email adapter does not support attachments");
  }

  const toAddresses = addressList(message.to);

  if (toAddresses === undefined) {
    throw new Error("SES transactional email requires at least one recipient");
  }

  return {
    FromEmailAddress: formatEmailAddress(message.from),
    Destination: {
      ToAddresses: toAddresses,
      CcAddresses: addressList(message.cc),
      BccAddresses: addressList(message.bcc),
    },
    ReplyToAddresses:
      message.replyTo === undefined ? undefined : [formatEmailAddress(message.replyTo)],
    ...(options?.configurationSetName === undefined
      ? {}
      : { ConfigurationSetName: options.configurationSetName }),
    Content: {
      Simple: {
        Subject: {
          Charset: "UTF-8",
          Data: message.subject,
        },
        Body: {
          ...(message.text === undefined
            ? {}
            : {
                Text: {
                  Charset: "UTF-8",
                  Data: message.text,
                },
              }),
          ...(message.html === undefined
            ? {}
            : {
                Html: {
                  Charset: "UTF-8",
                  Data: message.html,
                },
              }),
        },
        Headers:
          message.headers === undefined
            ? undefined
            : Object.entries(message.headers).map(([name, value]) => ({
                Name: name,
                Value: value,
              })),
      },
    },
  };
};

export const createSesEmailBinding = (
  input: CreateSesEmailBindingInput,
  client: SesClientLike = new SESv2Client({ region: input.region }),
): SendEmail => {
  return {
    send: async (message: EmailMessage | SendEmailBuilderInput): Promise<EmailSendResult> => {
      if (!("subject" in message)) {
        throw new Error("SES transactional email adapter requires builder-style messages");
      }

      const command = new SendEmailCommand(
        buildSesSendEmailInput(message, {
          configurationSetName: input.configurationSetName,
        }),
      );
      const result = await client.send(command);

      return {
        messageId: result.MessageId ?? "",
      };
    },
  };
};
