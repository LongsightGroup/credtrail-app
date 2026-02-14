interface QueueProcessorBindings {
  PLATFORM_DOMAIN: string;
  JOB_PROCESSOR_TOKEN?: string;
}

const queueProcessorUrl = (platformDomain: string): string => {
  return `https://${platformDomain}/v1/jobs/process`;
};

export const queueProcessorRequestFromSchedule = (env: QueueProcessorBindings): Request => {
  const headers = new Headers({
    'content-type': 'application/json',
  });
  const processorToken = env.JOB_PROCESSOR_TOKEN?.trim();

  if (processorToken !== undefined && processorToken.length > 0) {
    headers.set('authorization', `Bearer ${processorToken}`);
  }

  return new Request(queueProcessorUrl(env.PLATFORM_DOMAIN), {
    method: 'POST',
    headers,
    body: '{}',
  });
};
