interface MapConcurrentBoundedOptions {
  readonly concurrency: number;
}

/** Maps an input collection with bounded concurrency while preserving input order. */
export const mapConcurrentBounded = async <Input, Output>(
  inputs: readonly Input[],
  options: MapConcurrentBoundedOptions,
  mapInput: (input: Input, index: number) => Promise<Output>,
): Promise<readonly Output[]> => {
  if (!Number.isInteger(options.concurrency) || options.concurrency < 1) {
    throw new Error("mapConcurrentBounded concurrency must be a positive integer");
  }

  const completed: Array<{ readonly value: Output } | null> = Array.from(
    { length: inputs.length },
    () => null,
  );
  let nextIndex = 0;

  const mapNext = async (): Promise<void> => {
    while (nextIndex < inputs.length) {
      const index = nextIndex;
      nextIndex += 1;
      const input = inputs[index];

      if (input === undefined) {
        throw new Error("mapConcurrentBounded encountered an invalid input index");
      }

      completed[index] = {
        value: await mapInput(input, index),
      };
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(options.concurrency, inputs.length) }, () => mapNext()),
  );

  return completed.map((entry) => {
    if (entry === null) {
      throw new Error("mapConcurrentBounded completed without producing every result");
    }

    return entry.value;
  });
};
