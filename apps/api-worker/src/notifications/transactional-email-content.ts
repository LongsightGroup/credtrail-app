import { z } from "zod";
import { publicHttpUrl } from "../http/public-http-url";

const actionSchema = z.object({
  label: z.string().trim().min(1),
  url: z.url({ protocol: /^https?$/u }),
});

export const transactionalEmailContentSchema = z.object({
  institution: z.string().trim().min(1),
  image: z
    .object({
      url: z.string().refine((value) => publicHttpUrl(value) !== null),
      alt: z.string().trim().min(1),
    })
    .optional(),
  title: z.string().trim().min(1),
  paragraphs: z.array(z.string()).min(1),
  details: z.array(z.object({ label: z.string(), value: z.string() })).default([]),
  action: actionSchema,
  secondaryActions: z.array(actionSchema).default([]),
  footer: z.string().trim().min(1),
});

export type TransactionalEmailContent = z.input<typeof transactionalEmailContentSchema>;
