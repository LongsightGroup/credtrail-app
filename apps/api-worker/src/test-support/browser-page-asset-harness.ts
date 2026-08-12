type BrowserListener = (event?: FakeBrowserEvent) => void;

/** Minimal cancelable event substitute for page-asset behavior tests. */
export class FakeBrowserEvent {
  public defaultPrevented = false;

  /** Records that the page asset canceled the browser's default action. */
  public preventDefault(): void {
    this.defaultPrevented = true;
  }
}

const datasetName = (attributeName: string): string => {
  return attributeName.replace(/-([a-z])/g, (_match, letter: string) => letter.toUpperCase());
};

/** Minimal HTMLElement substitute shared by page-asset behavior tests. */
export class FakeElement {
  public readonly dataset: Record<string, string> = {};
  public children: FakeElement[] = [];
  public readonly classList: {
    add(...tokens: readonly string[]): void;
    contains(token: string): boolean;
    remove(...tokens: readonly string[]): void;
  };
  public className = "";
  public hidden = false;
  public readonly tagName: string;
  public textContent: string | null = "";
  private readonly listeners = new Map<string, BrowserListener[]>();

  public constructor(tagName = "DIV") {
    this.tagName = tagName;
    this.classList = {
      add: (...tokens): void => {
        const classes = new Set(this.className.split(/\s+/).filter((entry) => entry.length > 0));
        for (const token of tokens) {
          classes.add(token);
        }
        this.className = [...classes].join(" ");
      },
      contains: (token): boolean => this.className.split(/\s+/).includes(token),
      remove: (...tokens): void => {
        const removed = new Set(tokens);
        this.className = this.className
          .split(/\s+/)
          .filter((entry) => entry.length > 0 && !removed.has(entry))
          .join(" ");
      },
    };
  }

  /** Adds child nodes to this fake element. */
  public append(...children: FakeElement[]): void {
    this.children.push(...children);
  }

  /** Registers a listener for a browser event type. */
  public addEventListener(type: string, listener: BrowserListener): void {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  /** Dispatches a browser event to registered listeners. */
  public dispatch(type: string, event?: FakeBrowserEvent): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener(event);
    }
  }

  /** Replaces this fake element's children. */
  public replaceChildren(...children: FakeElement[]): void {
    this.children = [...children];
  }

  /** Records data attributes used by page-asset code. */
  public setAttribute(name: string, value: string): void {
    if (name.startsWith("data-")) {
      this.dataset[datasetName(name.slice("data-".length))] = value;
    }
  }

  /** Returns the first descendant matching the supported selector subset. */
  public querySelector(selector: string): FakeElement | null {
    return this.querySelectorAll(selector)[0] ?? null;
  }

  /** Returns descendants matching class and data-attribute selectors. */
  public querySelectorAll(selector: string): readonly FakeElement[] {
    return this.children.flatMap((child) => [
      ...(child.matches(selector) ? [child] : []),
      ...child.querySelectorAll(selector),
    ]);
  }

  private matches(selector: string): boolean {
    if (selector.startsWith(".")) {
      return this.classList.contains(selector.slice(1));
    }

    const attributes = [...selector.matchAll(/\[data-([a-z-]+)(?:="([^"]*)")?\]/g)];

    if (attributes.length === 0) {
      return false;
    }

    return attributes.every((match) => {
      const attributeName = match[1];

      if (attributeName === undefined) {
        return false;
      }

      const key = datasetName(attributeName);
      const expectedValue = match[2];
      return expectedValue === undefined
        ? key in this.dataset
        : this.dataset[key] === expectedValue;
    });
  }
}

/** Fake status element whose nested message node is always queryable. */
export class FakeStatusElement extends FakeElement {
  public readonly message = new FakeElement();

  public override querySelector(): FakeElement {
    return this.message;
  }
}

/** Minimal HTMLOptionElement substitute. */
export class FakeOption extends FakeElement {
  public disabled = false;
  public selected = false;
  public value = "";

  public constructor() {
    super("OPTION");
  }
}

/** Minimal HTMLInputElement substitute. */
export class FakeInput extends FakeElement {
  public checked = false;
  public disabled = false;
  public required = false;
  public type = "text";
  public value = "";

  public constructor() {
    super("INPUT");
  }
}

type FakeOptions = FakeOption[] & {
  item(index: number): FakeOption | null;
};

const fakeOptions = (options: readonly FakeOption[]): FakeOptions => {
  // SAFETY: the item method is installed immediately below, completing the fake collection shape.
  const collection = [...options] as FakeOptions;
  collection.item = (index): FakeOption | null => collection[index] ?? null;
  return collection;
};

/** Minimal HTMLSelectElement substitute with selectable option behavior. */
export class FakeSelect extends FakeElement {
  public disabled = false;
  public multiple = false;
  public required = false;
  public options = fakeOptions([]);
  private assignedValue = "";

  public constructor() {
    super("SELECT");
  }

  public override setAttribute(name: string, value: string): void {
    super.setAttribute(name, value);

    if (name === "multiple") {
      this.multiple = true;
    }

    if (name === "required") {
      this.required = true;
    }
  }

  public get selectedOptions(): readonly FakeOption[] {
    return this.options.filter((option) => option.selected);
  }

  public get value(): string {
    return this.selectedOptions[0]?.value ?? this.assignedValue;
  }

  public set value(value: string) {
    this.assignedValue = value;
    for (const option of this.options) {
      option.selected = option.value === value;
    }
  }

  public override replaceChildren(...options: FakeOption[]): void {
    super.replaceChildren(...options);
    this.options = fakeOptions(options);
  }

  public override append(...children: FakeElement[]): void {
    super.append(...children);
    const options = children.filter(
      (candidate): candidate is FakeOption => candidate instanceof FakeOption,
    );
    this.options = fakeOptions([...this.options, ...options]);
  }

  /** Inserts an option before another option. */
  public insertBefore(option: FakeOption, before: FakeOption): void {
    const beforeIndex = this.options.indexOf(before);
    const insertIndex = beforeIndex < 0 ? this.options.length : beforeIndex;
    this.options = fakeOptions([
      ...this.options.slice(0, insertIndex),
      option,
      ...this.options.slice(insertIndex),
    ]);
    super.replaceChildren(...this.options);
  }
}

/** Minimal document substitute that creates option nodes for picker tests. */
export class FakeDocument extends FakeElement {
  public createElement(tagName: string): FakeElement {
    return tagName.toLowerCase() === "option" ? new FakeOption() : new FakeElement(tagName);
  }
}

/** Deterministic timer queue for browser page-asset tests. */
export class FakeTimers {
  private nextId = 1;
  private readonly callbacks = new Map<number, BrowserListener>();

  public readonly setTimeout = (callback: BrowserListener): number => {
    const id = this.nextId;
    this.nextId += 1;
    this.callbacks.set(id, callback);
    return id;
  };

  public readonly clearTimeout = (id: number): void => {
    this.callbacks.delete(id);
  };

  /** Executes all currently queued timer callbacks. */
  public runAll(): void {
    const callbacks = [...this.callbacks.values()];
    this.callbacks.clear();

    for (const callback of callbacks) {
      callback();
    }
  }
}

/** Waits for asynchronous page-asset behavior to reach an observable condition. */
export const waitForBrowserCondition = async (
  predicate: () => boolean,
  failureMessage: string,
): Promise<void> => {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (predicate()) {
      return;
    }

    await new Promise<void>((resolve) => setImmediate(resolve));
  }

  throw new Error(failureMessage);
};
