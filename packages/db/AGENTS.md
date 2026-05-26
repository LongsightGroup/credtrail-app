# packages/db

New database code belongs in a focused domain slice under `src/`, not inline in
`src/index.ts`.

Keep `src/index.ts` as the public barrel for `@credtrail/db`: re-export domain
modules from there so existing callers can continue importing from the package
root.
