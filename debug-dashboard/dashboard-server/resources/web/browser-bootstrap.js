(function launchDashboard() {
  'use strict';

  const entry = document.currentScript?.dataset?.dashboardEntry;
  if (
    typeof entry !== 'string' ||
    !/^\/assets\/[A-Za-z0-9][A-Za-z0-9._-]*\.mjs$/.test(entry)
  ) {
    throw new Error('Dashboard bootstrap received an invalid entry path');
  }

  const isSealedUndefined = (descriptor) =>
    descriptor?.value === undefined &&
    descriptor?.writable === false &&
    descriptor?.enumerable === false &&
    descriptor?.configurable === false;
  const names = ['process', 'Deno'];

  for (const name of names) {
    const existing = Object.getOwnPropertyDescriptor(globalThis, name);
    if (existing === undefined || existing.configurable) {
      Object.defineProperty(globalThis, name, {
        value: undefined,
        writable: false,
        enumerable: false,
        configurable: false,
      });
    } else if (!isSealedUndefined(existing)) {
      throw new Error(`Dashboard bootstrap cannot seal unsafe ${name}`);
    }
  }

  for (const name of names) {
    const sealed = Object.getOwnPropertyDescriptor(globalThis, name);
    if (!isSealedUndefined(sealed)) {
      throw new Error(`Dashboard bootstrap failed to verify sealed ${name}`);
    }
  }

  return import(entry);
})();
