const vars = require("./vars");
// require("./logToFile");

const fs = require('fs');
const request = require("request");
// require('request-debug')(request);
const qs = require('querystring');
const parseXmlString = require("xml2js").parseString;

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const app = express();
app.set('trust proxy', 1); // trust first proxy
app.use(session({
    secret: vars.sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));
app.use(bodyParser.json());

// let swStats = require('swagger-stats');
// app.use(swStats.getMiddleware(vars.swagger));

console.log("hi!")

const port = 8689;

app.use("/.well-known", express.static(".well-known"));


app.get('/', (req, res) => {
    console.log("GET /")

    function sendRes(authenticated, userInfo) {
        if (userInfo) {
            try {
                let user = userInfo.osm.user[0];
                req.session.osmUserId = user["$"].id;
                req.session.osmUserName = user["$"].display_name;
            } catch (e) {
                console.warn(e);
            }
        }

        res.json({
            msg: "Hello World!",
            dev: vars.dev,
            time: new Date().getTime(),
            authenticated: authenticated,
            user: userInfo
        });
    }

    if (req.session.access_token && req.session.access_token_secret) {
        request({
            url: vars.osmUrl + "/api/0.6/user/details",
            method: "GET",
            oauth: {
                consumer_key: vars.osmKey, // Supply the consumer key, consumer secret, access token and access secret for every request to the API.
                consumer_secret: vars.osmSecret,
                token: req.session.access_token,
                token_secret: req.session.access_token_secret
            },
            headers: {
                "content-type": "text/xml" // Don't forget to set the content type as XML.
            }
        }, (err, rs, body) => {
            if (err) {
                console.error(err);
                res.status(500).json({ error: "unexpected error occurred" });
                return;
            }
            if (rs.statusCode < 200 || rs.statusCode > 230) {
                res.status(rs.statusCode).json({
                    error: "got non-ok status code from OSM (userinfo)",
                    coed: rs.statusCode,
                    msg: body
                });
                return;
            }

            parseXmlString(body, function (err, parsed) {
                if (err) {
                    console.warn(err);
                    res.status(500).json({ error: "failed to parse xml response" });
                    return;
                }
                sendRes(true, parsed);
            });
        });
    } else {
        sendRes(false, null);
    }


});

/// Auth Stuff

app.get("/auth", (req, res) => {
    console.log("GET /auth")
    // https://wiki.openstreetmap.org/wiki/OAuth_Server_side_Node.js_examples

    request.post({
        url: vars.reqUrl,
        oauth: {
            callback: vars.callbackUrl, // Supply a callback url. OSM uses the callback url later to return the key data to your application/website.
            consumer_key: vars.osmKey, // Consumer key and secret are given to the developer after registering the application on the official OSM site.
            consumer_secret: vars.osmSecret
        }
    }, (err, rs, body) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: "unexpected error occurred" });
            return;
        }
        if (rs.statusCode < 200 || rs.statusCode > 230) {
            res.status(rs.statusCode).json({
                error: "got non-ok status code from OSM (auth)",
                code: rs.statusCode,
                msg: body
            });
            return;
        }

        let bodyObject = qs.parse(body); // You can use the querystring package (const qs = require("querystring");) to parse the data to a javascript object.
        req.session.oauth_token = bodyObject.oauth_token; // Put the token and token secret in the session of this user.
        req.session.oauth_token_secret = bodyObject.oauth_token_secret;
        res.redirect(vars.authUrl + "?oauth_token=" + bodyObject.oauth_token); // This URL is used by the user to authorize. Send it to the client so that the client can use it. You could open a popup window or new tab with this URL so that the user can authorize on the official OSM site.
    });

});

app.get("/auth2", (req, res) => {
    console.log("GET /auth2")

    res.redirect(vars.auth2Url + "?client_id=" + vars.osmClientId + "&redirect_uri=" + encodeURIComponent(vars.callback2Url) + "&response_type=code&scope=read_prefs%20write_api");
});

app.get("/callback", (req, res) => {
    console.log("GET /callback")
    if (!req.session.oauth_token_secret) {
        res.status(401).json({ error: "invalid session (missing secret)" });
        return;
    }
    if (!req.query.oauth_token) {
        res.status(400).json({ error: "missing oauth token" });
        return;
    }
    if (!req.query.oauth_verifier) {
        res.status(400).json({ error: "missing oauth verifier" });
        return;
    }
    request({
        method: "POST",
        url: vars.accessUrl,
        oauth: {
            consumer_key: vars.osmKey, // Supply the consumer key, consumer secret, access token and access secret for every request to the API.
            consumer_secret: vars.osmSecret,
            token: req.query.oauth_token,
            token_secret: req.session.oauth_token_secret,
            verifier: req.query.oauth_verifier // The OSM callback contains this verifier. You need it to finalize the OAuth authentication process.
        }
    }, (err, rs, body) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: "unexpected error occurred" });
            return;
        }
        console.debug(body)
        if (rs.statusCode < 200 || rs.statusCode > 230) {
            res.status(rs.statusCode).json({
                error: "got non-ok status code from OSM (auth callback)",
                code: rs.statusCode,
                msg: body
            });
            return;
        }

        let bodyObject = qs.parse(body);
        req.session.access_token = bodyObject.oauth_token; // Save the access token and access secret in the user's session.
        req.session.access_token_secret = bodyObject.oauth_token_secret;

        //TODO
        res.redirect("https://osmbridge.trashapp.cc/appAuthCallback");
    });
});

app.get("/callback2", (req, res) => {
    console.log("GET /callback2")
    console.log(req.query)
    request({
        method: "POST",
        url: vars.token2Url,
        form: {
            client_id: vars.osmClientId,
            client_secret: vars.osmClientSecret,
            code: req.query.code,
            grant_type: "authorization_code",
            redirect_uri: vars.callback2Url
        }
    }, (err, rs, body) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: "unexpected error occurred" });
            return;
        }
        console.debug(body)
        if (rs.statusCode < 200 || rs.statusCode > 230) {
            res.status(rs.statusCode).json({
                error: "got non-ok status code from OSM (oauth2 callback)",
                code: rs.statusCode,
                msg: body
            });
            return;
        }

        let bodyObject = qs.parse(body);
        req.session.access_token = bodyObject.access_token; // Save the access token and access secret in the user's session.

        //TODO
        res.redirect("https://osmbridge.trashapp.cc/appAuthCallback");
    });
});

app.get("/appAuthCallback", (req, res) => {
    console.log("GET /appAuthCallback")
    res.send("<html>" +
        "   <head>" +
        "       <script>" +
        "           try {" +
        "               TrashApp.osmAuthCallback();" +
        "           } catch (e) {" +
        "               console.warn(e);" +
        "               alert('Please open this page from the TrashApp!');" +
        "           }" +
        "       </script>" +
        "   </head>" +
        "</html>")
});

app.get("/userinfo", (req, res) => {
    console.log("GET /userinfo")
    request({
        url: vars.osmUrl + "/api/0.6/user/details",
        method: "GET",
        oauth: {
            consumer_key: vars.osmKey, // Supply the consumer key, consumer secret, access token and access secret for every request to the API.
            consumer_secret: vars.osmSecret,
            token: req.session.access_token,
            token_secret: req.session.access_token_secret
        },
        headers: {
            "content-type": "text/xml" // Don't forget to set the content type as XML.
        }
    }, (err, rs, body) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: "unexpected error occurred" });
            return;
        }
        if (rs.statusCode < 200 || rs.statusCode > 230) {
            res.status(rs.statusCode).json({
                error: "got non-ok status code from OSM (userinfo)",
                coed: rs.statusCode,
                msg: body
            });
            return;
        }

        console.error("Uh oh!");
        res.send(body);
    });
});


/// /Auth Stuff


/*
{
    "comment": "A really important change",
    "trashcans": [
        {
            "lat": 5.17987,
            "lon": 7.12521,
            ("amenity": "waste_basket")
        }
    ]
}
 */
app.post("/create", (req, res) => {
    console.log("POST /create")
    if (!req.session.access_token || !req.session.access_token_secret) {
        res.status(403).json({ error: "Not authorized" });
        return;
    }

    if (!req.body) {
        res.status(400).json({ error: "missing body" });
        return;
    }

    console.log(" ");
    console.log("==============================")
    console.log("New /create request");
    console.log(req.session.osmUserName + " (" + req.session.osmUserId + ")");
    let userAgent = req.header("User-Agent");
    console.log(userAgent);

    let comment = req.body.comment;
    if (!comment) {
        res.status(400).json({ error: "missing comment" });
        return;
    }
    console.log("Comment: \"" + comment + "\"");

    let trashcans = req.body.trashcans;
    if (!trashcans || trashcans.length === 0) {
        res.status(400).json({ error: "trashcans cannot be missing/empty" });
        return;
    }
    console.log("Trashcans: " + JSON.stringify(trashcans));
    console.log(" ");

    fs.readFile("./create_changeset.xml", "utf8", (err, createChangesetData) => {
        if (err) {
            console.error("Failed to read changeset template", err);
            res.status(500).json({ error: "unexpected error occurred while loading changeset template" });
            return;
        }


        let createChangeset = createChangesetData.replace(/__comment__/gi, comment);
        console.log(createChangeset);


        // Create Changeset
        request({
            url: vars.osmUrl + "/api/0.6/changeset/create",
            method: "PUT",
            body: createChangeset,
            oauth: {
                consumer_key: vars.osmKey, // Supply the consumer key, consumer secret, access token and access secret for every request to the API.
                consumer_secret: vars.osmSecret,
                token: req.session.access_token,
                token_secret: req.session.access_token_secret
            },
            headers: { "Content-Type": "text/xml" }
        }, function (err, rs, body) {
            if (err) {
                console.error(err);
                res.status(500).json({ error: "unexpected error occurred while creating changeset" });
                return;
            }
            if (rs.statusCode < 200 || rs.statusCode > 230) {
                res.status(rs.statusCode).json({
                    error: "got non-ok status code from OSM (create changeset)",
                    code: rs.statusCode,
                    msg: body
                });
                return;
            }

            let changesetId = body;
            console.log("Created new changeset #" + changesetId);

            fs.readFile("./upload_changes.xml", "utf8", (err, uploadChangesData) => {
                if (err) {
                    console.error("Failed to read changes template", err);
                    res.status(500).json({ error: "unexpected error occurred while loading changes template" });
                    return;
                }

                fs.readFile("./create_node.xml", "utf8", (err, createNodeData) => {
                    if (err) {
                        console.error("Failed to read node template", err);
                        res.status(500).json({ error: "unexpected error occurred while loading node template" });
                        return;
                    }

                    let createNodes = [];
                    for (let i = 0; i < trashcans.length; i++) {
                        let trashcan = trashcans[i];
                        if (!trashcan.amenity) {
                            trashcan.amenity = "waste_basket";
                        }
                        if (!trashcan.lat || !trashcan.lon) {
                            console.warn("Missing lat/lon!");
                            continue;
                        }

                        let extraTag = "";
                        if (trashcan.amenity === "waste_basket") {
                            if (trashcan.waste && typeof trashcan.waste === "string") {
                                extraTag = '<tag k="waste" v="' + trashcan.waste + '"/>';
                            }
                        }
                        if (trashcan.amenity === "recycling") {
                            if (trashcan.recycling && typeof trashcan.recycling === "string") {
                                let recyclingSplit = trashcan.recycling.split(',');
                                for (let j = 0; j < recyclingSplit.length; j++) {
                                    extraTag += '<tag k="recycling:' + recyclingSplit[j] + '" v="yes"/>\n';
                                }
                            }
                        }

                        let node = createNodeData
                            .replace(/__id__/gi, (-1 - i))
                            .replace(/__lat__/gi, trashcan.lat)
                            .replace(/__lon__/gi, trashcan.lon)
                            .replace(/__amenity__/gi, trashcan.amenity)
                            .replace(/__changeset__/gi, changesetId)
                            .replace("<another-tag-to-replace/>", extraTag);
                        createNodes.push(node);
                    }

                    if (createNodes.length === 0) {
                        console.warn("Parsed array is empty! Aborting!");
                        res.status(400).json({ error: "Failed to parse any of the submitted trashcans" });
                        return;
                    }


                    let changesXml = createNodes.join("\n");
                    let uploadChanges = uploadChangesData.replace(/<the-changes-replace-me\/>/gi, changesXml);
                    console.log(uploadChanges);

                    // Upload Changeset
                    request({
                        url: vars.osmUrl + "/api/0.6/changeset/" + changesetId + "/upload",
                        method: "POST",
                        body: uploadChanges,
                        oauth: {
                            consumer_key: vars.osmKey, // Supply the consumer key, consumer secret, access token and access secret for every request to the API.
                            consumer_secret: vars.osmSecret,
                            token: req.session.access_token,
                            token_secret: req.session.access_token_secret
                        },
                        headers: { "Content-Type": "text/xml" }
                    }, function (err, rs, body) {
                        if (err) {
                            console.error(err);
                            res.status(500).json({ error: "unexpected error occurred while uploading changeset" });
                            return;
                        }
                        if (rs.statusCode < 200 || rs.statusCode > 230) {
                            res.status(rs.statusCode).json({
                                error: "got non-ok status code from OSM (upload changeset)",
                                code: rs.statusCode,
                                msg: body
                            });
                            return;
                        }

                        console.log("Uploaded data for changeset #" + changesetId + " with " + createNodes.length + " additions");
                        console.log(body);

                        parseXmlString(body, function (err, parsed) {
                            if (err) {
                                console.warn(err);
                                res.status(500).json({ error: "failed to parse xml response" });
                                return;
                            }
                            console.log(JSON.stringify(parsed));

                            let newNodeIds = [];
                            try {
                                let nodes = parsed.diffResult["$"].node;
                                for (let n = 0; n < nodes.length; n++) {
                                    newNodeIds.push(nodes[n]["$"].new_id);
                                }
                            } catch (e) {// just being careful
                                console.warn(e);
                            }

                            // Close Changeset
                            request({
                                url: vars.osmUrl + "/api/0.6/changeset/" + changesetId + "/close",
                                method: "PUT",
                                oauth: {
                                    consumer_key: vars.osmKey, // Supply the consumer key, consumer secret, access token and access secret for every request to the API.
                                    consumer_secret: vars.osmSecret,
                                    token: req.session.access_token,
                                    token_secret: req.session.access_token_secret
                                },
                                headers: { "Content-Type": "text/xml" }
                            }, function (err, rs, body) {
                                if (err) {
                                    console.error(err);
                                    res.status(500).json({ error: "unexpected error occurred while closing changeset" });
                                    return;
                                }
                                if (rs.statusCode < 200 || rs.statusCode > 230) {
                                    res.status(rs.statusCode).json({
                                        error: "got non-ok status code from OSM (close changeset)",
                                        code: rs.statusCode,
                                        msg: body
                                    });
                                    return;
                                }

                                console.log("Closed changeset #" + changesetId);
                                console.log("==============================")

                                res.json({ msg: "success", dev: vars.dev, changeset: changesetId, nodes: newNodeIds });
                                console.log(" ");
                            });
                        });
                    });
                });


            })
        })
    });

});

// proxy for overpass
app.post("/interpreter", (req, res) => {
    console.log("proxying interpreter from " + req.header("User-Agent") + " " + getIp(req));
    let rqst = request({
        method: "POST",
        url: "https://www.overpass-api.de/api/interpreter"
    }, function (error, response, body) {
        console.error('error:', error); // Print the error if one occurred
        console.log('statusCode:', response && response.statusCode); // Print the response status code if a response was received
        // console.log('body:', body); // Print the HTML for the Google homepage.
    })
        // .on('response', function (response, body) {
        //     console.log(response.statusCode)
        // })
        .on('error', function (err) {
            console.warn("interpreter error");
            console.error(err)
        });
    req.pipe(rqst).pipe(res);
})

function getIp(req) {
    return req.get('cf-connecting-ip') || req.get('x-forwarded-for') || req.get("x-real-ip") || req.connection.remoteAddress || req.ip;
}

if (vars.dev) {
    console.warn("RUNNING IN DEV MODE!");
}

app.listen(port, () => console.log(`OsmBridge listening on port ${ port }!`));

process.on('uncaughtException', function (err) {
    console.log('Caught exception: ');
    console.log(err)
});
