const DEV = (process.env.NODE_ENV === "development") || true;


module.exports = {
    dev: DEV,

    //Note: It's *really* important to make sure there's only one / in the request URL,
    // or the API will return a super useful "Couldn't authenticate you" error with no context whatsoever
    osmUrl: DEV ? "https://master.apis.dev.openstreetmap.org" : "https://api.openstreetmap.org",

    reqUrl: DEV ? "https://master.apis.dev.openstreetmap.org/oauth/request_token" : "https://www.openstreetmap.org/oauth/request_token",
    accessUrl: DEV ? "https://master.apis.dev.openstreetmap.org/oauth/access_token" : "https://www.openstreetmap.org/oauth/access_token",
    authUrl: DEV ? "https://master.apis.dev.openstreetmap.org/oauth/authorize" : "https://www.openstreetmap.org/oauth/authorize",

    callbackUrl: "https://osmbridge.trashapp.cc/callback",

    osmKey: DEV ? "xxx" : "xxx",
    osmSecret: DEV ? "xxx" : "xxx",

    sessionSecret: "keyboard cat"
};