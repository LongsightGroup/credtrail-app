import React from "hono/jsx";

const runtimeGlobal = globalThis as typeof globalThis & {
  React?: typeof React;
};

runtimeGlobal.React = React;
