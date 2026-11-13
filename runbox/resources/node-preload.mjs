import { validateSession, guardedFetch } from './node-session.mjs';

const value = validateSession();
globalThis.fetch = guardedFetch(globalThis.fetch, value);
