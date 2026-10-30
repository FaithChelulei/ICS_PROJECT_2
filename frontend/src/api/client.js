// Thin fetch wrapper for the Express backend. Every real screen goes
// through this -- no component calls fetch() directly -- so the token
// handling and the "your session was revoked" behaviour live in one place.
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:4000';

let authToken = null;
let onUnauthorized = null;

// A browser can't report its real computer name, so each browser profile
// gets a random, stable device id the first time it opens the app. It's
// sent on every request as X-Device-Name and is what the risk model's
// is_own_pc / unique_pcs_used_that_day features are computed from (the
// live stand-in for CERT's per-PC logon records). Clearing site data or
// using a different browser = a new device, which is exactly the "sign-in
// from an unrecognised device" signal those features exist to catch.
const DEVICE_KEY = 'childguard_device_id';

function getDeviceId() {
  try {
    let id = localStorage.getItem(DEVICE_KEY);
    if (!id) {
      const rand =
        typeof crypto !== 'undefined' && crypto.randomUUID
          ? crypto.randomUUID()
          : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
      id = `browser-${rand.slice(0, 8)}`;
      localStorage.setItem(DEVICE_KEY, id);
    }
    return id;
  } catch {
    return null; // storage blocked -- backend treats a missing name as "own device"
  }
}

export function setAuthToken(token) {
  authToken = token;
}

// App.jsx registers this once, at the top, so a 401 from ANY request
// (e.g. a risk-response force-revoke that lands mid-session) routes the
// whole app back to the login screen -- not just the one component that
// happened to be fetching.
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

// Identical GETs already in flight share one request. React StrictMode runs
// every mount effect twice in dev, which doubled each dashboard's list call
// -- and every backend request is logged as an event for the risk model, so
// the duplicates alone pushed normal sessions over the logout threshold.
const inFlightGets = new Map();

export function apiFetch(path, options = {}) {
  const { method = 'GET', auth = true } = options;
  if (method !== 'GET') return doFetch(path, options);

  const key = `${auth ? authToken : ''} ${path}`;
  if (!inFlightGets.has(key)) {
    inFlightGets.set(key, doFetch(path, options).finally(() => inFlightGets.delete(key)));
  }
  return inFlightGets.get(key);
}

async function doFetch(path, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth && authToken) headers.Authorization = `Bearer ${authToken}`;
  const deviceId = getDeviceId();
  if (deviceId) headers['X-Device-Name'] = deviceId;

  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  const isJson = res.headers.get('content-type')?.includes('application/json');
  const data = isJson ? await res.json() : null;

  if (res.status === 401 && auth && onUnauthorized) {
    onUnauthorized(data);
  }

  if (!res.ok) {
    const error = new Error(data?.error || `Request failed (${res.status})`);
    error.status = res.status;
    error.code = data?.code;
    throw error;
  }

  return data;
}
