// @ts-check
/**
 * WebAuthn (passkey) helpers: convert the server's JSON options (go-webauthn: {publicKey: {...}} with base64url
 * binary fields) to the browser API and serialise credentials back to JSON.
 *
 *   const opts = toGetOptions(res.options);            // → CredentialRequestOptions
 *   const cred = await navigator.credentials.get(opts);
 *   await api.post('/auth/passkey/finish', {flow_id, credential: credentialToJSON(cred)});
 *
 * passkeysAvailable(rpId) is false when the page's hostname is not the RP ID (or a subdomain of it) — browsers
 * reject the ceremony then (§18.1), so the UI hides passkey buttons.
 * @module core/webauthn
 */

/** @param {string} s base64url */
export function b64urlToBuf(s) {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

/** @param {ArrayBuffer | ArrayBufferView | null | undefined} buf */
export function bufToB64url(buf) {
  if (!buf) return '';
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 1) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * @param {string | undefined} rpId
 * @returns {boolean}
 */
export function passkeysAvailable(rpId) {
  if (!window.isSecureContext || typeof window.PublicKeyCredential === 'undefined') return false;
  if (!rpId) return true;
  const host = location.hostname;
  return host === rpId || host.endsWith(`.${rpId}`);
}

/** @param {any} json */
function unwrap(json) {
  if (!json) return {};
  if (json.publicKey) return json.publicKey;
  if (json.options) return unwrap(json.options);
  return json;
}

/**
 * Registration options (navigator.credentials.create).
 * @param {any} json server options
 * @returns {CredentialCreationOptions}
 */
export function toCreateOptions(json) {
  const pk = unwrap(json);
  const PKC = /** @type {any} */ (window.PublicKeyCredential);
  if (PKC && typeof PKC.parseCreationOptionsFromJSON === 'function') {
    return { publicKey: PKC.parseCreationOptionsFromJSON(pk) };
  }
  return {
    publicKey: {
      ...pk,
      challenge: b64urlToBuf(pk.challenge),
      user: { ...pk.user, id: b64urlToBuf(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials || []).map((/** @type {any} */ c) => ({ ...c, id: b64urlToBuf(c.id) })),
    },
  };
}

/**
 * Authentication options (navigator.credentials.get).
 * @param {any} json server options
 * @param {{conditional?: boolean, signal?: AbortSignal}} [opts]
 * @returns {CredentialRequestOptions}
 */
export function toGetOptions(json, opts = {}) {
  const pk = unwrap(json);
  const PKC = /** @type {any} */ (window.PublicKeyCredential);
  /** @type {any} */
  let publicKey;
  if (PKC && typeof PKC.parseRequestOptionsFromJSON === 'function') publicKey = PKC.parseRequestOptionsFromJSON(pk);
  else {
    publicKey = {
      ...pk,
      challenge: b64urlToBuf(pk.challenge),
      allowCredentials: (pk.allowCredentials || []).map((/** @type {any} */ c) => ({ ...c, id: b64urlToBuf(c.id) })),
    };
  }
  /** @type {any} */
  const out = { publicKey };
  if (opts.conditional) out.mediation = 'conditional';
  if (opts.signal) out.signal = opts.signal;
  return out;
}

/**
 * Serialise a PublicKeyCredential for the server.
 * @param {any} cred
 * @returns {Record<string, any>}
 */
export function credentialToJSON(cred) {
  if (cred && typeof cred.toJSON === 'function') {
    try { return cred.toJSON(); } catch { /* fall through (some browsers throw for extensions) */ }
  }
  const r = cred.response;
  /** @type {Record<string, any>} */
  const response = { clientDataJSON: bufToB64url(r.clientDataJSON) };
  if (r.attestationObject) {
    response.attestationObject = bufToB64url(r.attestationObject);
    if (typeof r.getTransports === 'function') response.transports = r.getTransports();
  }
  if (r.authenticatorData) response.authenticatorData = bufToB64url(r.authenticatorData);
  if (r.signature) response.signature = bufToB64url(r.signature);
  if (r.userHandle) response.userHandle = bufToB64url(r.userHandle);
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment || undefined,
    clientExtensionResults: typeof cred.getClientExtensionResults === 'function' ? cred.getClientExtensionResults() : {},
    response,
  };
}

/** @returns {Promise<boolean>} true when the browser supports passkey autofill (conditional mediation). */
export async function conditionalMediationAvailable() {
  const PKC = /** @type {any} */ (window.PublicKeyCredential);
  try {
    return !!(PKC && typeof PKC.isConditionalMediationAvailable === 'function' && (await PKC.isConditionalMediationAvailable()));
  } catch {
    return false;
  }
}
