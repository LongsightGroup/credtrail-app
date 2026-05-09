export default {
  source: ["design/tokens/**/*.json"],
  platforms: {
    css: {
      transformGroup: "css",
      buildPath: "apps/api-worker/src/ui/page-assets/content/generated/",
      files: [
        {
          destination: "design-tokens.css",
          format: "css/variables",
          options: {
            selector: ":root",
            outputReferences: true
          }
        }
      ]
    }
  }
};
