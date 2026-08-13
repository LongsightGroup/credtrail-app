import { test } from "@playwright/test";

import {
  completeFirstDayWorkflow,
  createFirstDayWorkflowIdentity,
} from "./helpers/first-day-workflow";

test("an administrator can create a badge and issue it through the normal workflow", async ({
  page,
}) => {
  await completeFirstDayWorkflow(page, createFirstDayWorkflowIdentity());
});
