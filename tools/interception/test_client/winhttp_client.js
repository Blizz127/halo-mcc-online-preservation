// Minimal Windows HTTPS test client for the Proton/Wine prefix (Stage A / C).
//
// Run with the prefix's own cscript.exe, e.g.:
//   WINEPREFIX=<prefix> <proton>/files/bin/wine cscript.exe //nologo Z:\path\winhttp_client.js <url> [proxy]
//
// Uses WinHttp.WinHttpRequest.5.1 deliberately: WinHTTP is the stack a Windows
// title is most likely to use, it consults the WinHTTP proxy configuration
// rather than the WinINET/browser one, and it validates server certificates
// against the Windows (here, Wine) certificate store. That makes it a useful
// stand-in for how MCC might behave, without needing a compiler in the prefix.
//
// Output is deliberately built as plain `key=value` lines rather than JSON:
// the JScript engine in Wine's Windows Script Host does not reliably provide a
// native `JSON` object, and a `JSON.stringify` call throws a ReferenceError
// that produces NO output at all - which reads as "the client never ran" when
// in fact it ran and failed. Plain string building cannot fail that way.
//
// Sends no credentials. Prints only status, a body LENGTH, and error codes -
// never a body and never a header value.

function emit(key, value) {
    WScript.Echo(key + "=" + value);
}

var url = WScript.Arguments.Length > 0 ? WScript.Arguments(0) : "https://p0c2a.test:8443/p0c2a-test";
var proxy = WScript.Arguments.Length > 1 ? WScript.Arguments(1) : "";
// WinHTTP bypasses the proxy for loopback by default, which makes a
// loopback-hosted test service look like "the proxy was ignored". The special
// "<-loopback>" bypass token disables that automatic bypass, so a local test
// actually exercises the proxy path.
var bypass = WScript.Arguments.Length > 2 ? WScript.Arguments(2) : "<-loopback>";

emit("client", "winhttp");
emit("url", url);
emit("proxy", proxy === "" ? "(none)" : proxy);

var req = null;
try {
    req = new ActiveXObject("WinHttp.WinHttpRequest.5.1");
    emit("com_object", "created");
} catch (e) {
    emit("com_object", "FAILED");
    emit("error_number", (e.number >>> 0).toString(16));
    emit("error_description", e.description);
    WScript.Quit(2);
}

try {
    if (proxy !== "") {
        // 2 = HTTPREQUEST_PROXYSETTING_PROXY (explicit proxy for this request)
        req.SetProxy(2, proxy, bypass);
        emit("proxy_mode", "explicit");
        emit("proxy_bypass", bypass);
    } else {
        emit("proxy_mode", "default");
    }

    req.Open("GET", url, false);
    req.SetRequestHeader("User-Agent", "p0c2a-winhttp-test-client");
    req.Send();

    emit("result", "ok");
    emit("status", req.Status);
    emit("body_length", ("" + req.ResponseText).length);
} catch (e) {
    // WinHTTP reports TLS trust failure as 0x80072F0D (ERROR_WINHTTP_SECURE_FAILURE).
    emit("result", "error");
    emit("error_number", (e.number >>> 0).toString(16));
    emit("error_description", e.description);
}
