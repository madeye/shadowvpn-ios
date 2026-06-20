#!/usr/bin/env python3
"""Push ShadowVPN App Store metadata via the App Store Connect API.

Requires the app record to already exist (Apple forbids creating apps via API).
Reads scripts/asc/metadata.json and upserts:
  - primary category on the (editable) AppInfo
  - AppInfoLocalizations (name, subtitle, privacyPolicyUrl)
  - AppStoreVersionLocalizations (description, keywords, urls, promo text)
for each locale present in the metadata file.
"""
import json, time, os, sys, jwt, urllib.request, urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
BUNDLE_ID = "com.tangzixiang.shadowvpn"
CFG = json.load(open("/Users/mlv/.appstoreconnect/api_key_tangzixiang.json"))
KEY_ID, ISSUER = CFG["key_id"], CFG["issuer_id"]
PEM = CFG.get("key") or CFG.get("pem")
META = json.load(open(os.path.join(HERE, "metadata.json")))
BASE = "https://api.appstoreconnect.apple.com"


def token():
    now = int(time.time())
    return jwt.encode({"iss": ISSUER, "iat": now, "exp": now + 1200,
                       "aud": "appstoreconnect-v1"}, PEM,
                      algorithm="ES256", headers={"kid": KEY_ID, "typ": "JWT"})


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + token())
    req.add_header("Content-Type", "application/json")
    try:
        r = urllib.request.urlopen(req)
        return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def must(st, resp, ctx):
    if st >= 300:
        print(f"  ! {ctx}: {st}\n{json.dumps(resp, indent=2)}")
        sys.exit(1)
    return resp


def find_app():
    st, r = call("GET", f"/v1/apps?filter[bundleId]={BUNDLE_ID}"
                        "&include=appInfos&limit=1")
    must(st, r, "find app")
    if not r.get("data"):
        print(f"  ! No app record for {BUNDLE_ID}. Create it in App Store "
              "Connect first (Apple forbids creating apps via API).")
        sys.exit(2)
    app = r["data"][0]
    app_infos = [x for x in r.get("included", []) if x["type"] == "appInfos"]
    return app["id"], app_infos


def editable_version(app_id):
    st, r = call("GET", f"/v1/apps/{app_id}/appStoreVersions?limit=10")
    must(st, r, "list versions")
    editable = {"PREPARE_FOR_SUBMISSION", "DEVELOPER_REJECTED",
                "REJECTED", "METADATA_REJECTED", "WAITING_FOR_REVIEW",
                "INVALID_BINARY"}
    for v in r.get("data", []):
        if v["attributes"]["appStoreState"] in editable:
            return v["id"]
    # none editable -> create a 1.0 version
    st, r = call("POST", "/v1/appStoreVersions", {
        "data": {"type": "appStoreVersions",
                 "attributes": {"platform": "IOS", "versionString": "1.0"},
                 "relationships": {"app": {"data": {"type": "apps", "id": app_id}}}}})
    must(st, r, "create version")
    return r["data"]["id"]


def editable_app_info(app_id):
    st, r = call("GET", f"/v1/apps/{app_id}/appInfos?limit=10")
    must(st, r, "list appInfos")
    editable = {"PREPARE_FOR_SUBMISSION", "DEVELOPER_REJECTED", "REJECTED",
                "METADATA_REJECTED", "WAITING_FOR_REVIEW"}
    for ai in r.get("data", []):
        if ai["attributes"].get("appStoreState") in editable \
           or ai["attributes"].get("state") in editable:
            return ai["id"]
    return r["data"][0]["id"] if r.get("data") else None


def set_category(app_info_id, cat):
    st, r = call("PATCH", f"/v1/appInfos/{app_info_id}", {
        "data": {"type": "appInfos", "id": app_info_id,
                 "relationships": {"primaryCategory": {
                     "data": {"type": "appCategories", "id": cat}}}}})
    must(st, r, "set category")
    print(f"  category -> {cat}")


def upsert(kind, parent_path, parent_rel, parent_id, loc, attrs):
    """kind: appInfoLocalizations | appStoreVersionLocalizations"""
    st, r = call("GET", f"{parent_path}/{parent_id}/{kind[0].lower()+kind[1:]}?limit=50")
    must(st, r, f"list {kind}")
    existing = {x["attributes"]["locale"]: x["id"] for x in r.get("data", [])}
    if loc in existing:
        st, r = call("PATCH", f"/v1/{kind}/{existing[loc]}", {
            "data": {"type": kind, "id": existing[loc], "attributes": attrs}})
        must(st, r, f"patch {kind} {loc}")
        print(f"  {kind} {loc} updated")
    else:
        body = {"data": {"type": kind,
                         "attributes": dict(attrs, locale=loc),
                         "relationships": {parent_rel: {"data": {
                             "type": parent_path.split('/')[-1], "id": parent_id}}}}}
        st, r = call("POST", f"/v1/{kind}", body)
        must(st, r, f"create {kind} {loc}")
        print(f"  {kind} {loc} created")


def main():
    app_id, _ = find_app()
    print(f"App: {app_id} ({BUNDLE_ID})")
    ver_id = editable_version(app_id)
    ai_id = editable_app_info(app_id)
    print(f"  version={ver_id} appInfo={ai_id}")

    if META.get("primaryCategory") and ai_id:
        set_category(ai_id, META["primaryCategory"])

    for loc, a in META.get("appInfo", {}).items():
        upsert("appInfoLocalizations", "/v1/appInfos", "appInfo", ai_id, loc, a)

    for loc, a in META.get("version", {}).items():
        upsert("appStoreVersionLocalizations", "/v1/appStoreVersions",
               "appStoreVersion", ver_id, loc, a)

    print("Done.")


if __name__ == "__main__":
    main()
