const inlineEventHandlerAttributePattern = /^on/i;

const noInlineJsxEventHandlers = {
  meta: {
    type: "problem",
    docs: {
      description: "Disallow inline event-handler attributes in server-rendered JSX.",
    },
    schema: [],
    messages: {
      inlineEventHandler:
        "Do not use the inline event-handler attribute '{{attributeName}}'. The Content Security Policy blocks inline handlers; use a server-submitted form or an approved page asset.",
    },
  },
  create(context) {
    return {
      JSXAttribute(node) {
        if (
          node.name.type !== "JSXIdentifier" ||
          !inlineEventHandlerAttributePattern.test(node.name.name)
        ) {
          return;
        }

        context.report({
          node: node.name,
          messageId: "inlineEventHandler",
          data: { attributeName: node.name.name },
        });
      },
    };
  },
};

export default {
  meta: {
    name: "credtrail",
  },
  rules: {
    "no-inline-jsx-event-handlers": noInlineJsxEventHandlers,
  },
};
