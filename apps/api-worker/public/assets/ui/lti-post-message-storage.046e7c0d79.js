(() => {
const root = document.getElementById("lti-post-message-storage-redirect");
if (!(root instanceof HTMLElement)) {
  return;
}

const { authorizationRedirectUrl, platformOrigin, storageTarget, state, nonce } = root.dataset;

if (!authorizationRedirectUrl || !platformOrigin || !storageTarget || !state || !nonce) {
  return;
}

const entries = [
  {
    key: `state_${state}`,
    value: state,
  },
  {
    key: `nonce_${nonce}`,
    value: nonce,
  },
];

const redirect = () => {
  window.location.replace(authorizationRedirectUrl);
};

const parentWindow = window.parent !== window ? window.parent : window.opener;
if (!parentWindow) {
  redirect();
  return;
}

const targetFrame =
  storageTarget === "_parent" ? parentWindow : parentWindow.frames[storageTarget];

if (!targetFrame) {
  redirect();
  return;
}

const postToStorageFrame = (message) => {
  targetFrame.postMessage(JSON.stringify(message), platformOrigin);
};
const pending = new Set(entries.map((entry) => entry.key));
const createMessageId = () => {
  if (crypto.randomUUID) {
    return crypto.randomUUID();
  }

  return `credtrail-lti-${Date.now()}-${Math.random().toString(16).slice(2)}`;
};
const messageIds = new Map(entries.map((entry) => [createMessageId(), entry.key]));
const timeout = window.setTimeout(redirect, 1500);
let storageMessagesPosted = false;

const postStorageMessages = () => {
  if (storageMessagesPosted) {
    return;
  }

  storageMessagesPosted = true;

  for (const [messageId, key] of messageIds.entries()) {
    const entry = entries.find((candidate) => candidate.key === key);
    if (entry === undefined) {
      continue;
    }

    postToStorageFrame({
      subject: "lti.put_data",
      message_id: messageId,
      key: entry.key,
      value: entry.value,
    });
  }
};

window.addEventListener("message", (event) => {
  if (event.origin !== platformOrigin) {
    return;
  }

  let message = event.data;
  if (typeof message === "string") {
    try {
      message = JSON.parse(message);
    } catch {
      return;
    }
  }

  if (typeof message !== "object" || message === null) {
    return;
  }

  if (message.subject === "org.sakailms.lti.prelaunch.response") {
    postStorageMessages();
    return;
  }

  if (message.subject !== "lti.put_data.response") {
    return;
  }

  const key = messageIds.get(message.message_id);
  if (key === undefined) {
    return;
  }

  if (message.error === undefined) {
    pending.delete(key);
  }

  if (pending.size === 0) {
    window.clearTimeout(timeout);
    redirect();
  }
});

postToStorageFrame({ subject: "org.sakailms.lti.prelaunch" });
window.setTimeout(postStorageMessages, 250);

})();