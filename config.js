const env = process.env;

// Use the OSM dev API unless explicitly disabled (defaults to dev, like the old vars.js)
const DEV = (env.OSM_DEV || "true") === "true";

const OSM_API_URL = DEV ? "https://master.apis.dev.openstreetmap.org" : "https://api.openstreetmap.org";
const OSM_WEB_URL = DEV ? "https://master.apis.dev.openstreetmap.org" : "https://www.openstreetmap.org";

const PUBLIC_URL = (env.PUBLIC_URL || "https://osmbridge.trashapp.cc").replace(/\/+$/, "");

for (const key of ["SESSION_SECRET", "OSM_CLIENT_ID", "OSM_CLIENT_SECRET"]) {
    if (!env[key]) {
        console.error("Missing required env var " + key);
        process.exit(1);
    }
}

module.exports = {
    dev: DEV,
    port: parseInt(env.PORT || "8689"),
    publicUrl: PUBLIC_URL,

    //Note: It's *really* important to make sure there's only one / in the request URL,
    // or the API will return a super useful "Couldn't authenticate you" error with no context whatsoever
    osmUrl: OSM_API_URL,

    reqUrl: OSM_WEB_URL + "/oauth/request_token",
    accessUrl: OSM_WEB_URL + "/oauth/access_token",
    authUrl: OSM_WEB_URL + "/oauth/authorize",

    auth2Url: OSM_WEB_URL + "/oauth2/authorize",
    token2Url: OSM_WEB_URL + "/oauth2/token",

    callbackUrl: PUBLIC_URL + "/callback",
    callback2Url: PUBLIC_URL + "/callback2",

    // OAuth 1 (deprecated)
    osmKey: env.OSM_KEY,
    osmSecret: env.OSM_SECRET,

    // OAuth 2
    osmClientId: env.OSM_CLIENT_ID,
    osmClientSecret: env.OSM_CLIENT_SECRET,

    overpassUrl: env.OVERPASS_URL || "https://www.overpass-api.de/api/interpreter",

    sessionSecret: env.SESSION_SECRET
};
