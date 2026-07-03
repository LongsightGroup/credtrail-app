import "./node-jsx-runtime";
import { serve } from "@hono/node-server";
import { app } from "./app";
import {
  createNodeExecutionContext,
  createNodeRuntimeBindings,
  parseNodeRuntimePort,
} from "./runtime/node-runtime";

const workerBindings = createNodeRuntimeBindings(process.env);
const executionContext = createNodeExecutionContext();
const port = parseNodeRuntimePort(process.env);

serve(
  {
    port,
    hostname: "0.0.0.0",
    fetch: (request) => {
      return app.fetch(request, workerBindings, executionContext);
    },
  },
  (info) => {
    console.info(
      JSON.stringify({
        message: "node_server_started",
        host: info.address,
        port: info.port,
      }),
    );
  },
);
