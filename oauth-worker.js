/**
 * FlowOS GitHub OAuth exchange endpoint
 *
 * Deploy this file as a Cloudflare Worker.
 * Secrets:
 *   GITHUB_CLIENT_ID
 *   GITHUB_CLIENT_SECRET
 *
 * The public GitHub Pages app sends the temporary OAuth code here.
 * The worker exchanges it server-side so the GitHub client secret
 * never appears in index.html.
 */

const ALLOWED_ORIGIN = "https://22xshun.github.io";

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const cors = {
      "Access-Control-Allow-Origin": origin === ALLOWED_ORIGIN ? ALLOWED_ORIGIN : "null",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method !== "POST") {
      return new Response(JSON.stringify({ error: "method_not_allowed" }), {
        status: 405, headers: cors
      });
    }

    try {
      const body = await request.json();
      const code = String(body.code || "");
      const redirectUri = String(body.redirect_uri || "");
      const codeVerifier = String(body.code_verifier || "");

      if (!code || !codeVerifier) {
        return new Response(JSON.stringify({ error: "missing_code_or_verifier" }), {
          status: 400, headers: cors
        });
      }

      if (redirectUri !== ALLOWED_ORIGIN + "/") {
        return new Response(JSON.stringify({ error: "invalid_redirect_uri" }), {
          status: 400, headers: cors
        });
      }

      const tokenResponse = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Accept": "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          client_id: env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: redirectUri,
          code_verifier: codeVerifier
        })
      });

      const data = await tokenResponse.json();

      if (!tokenResponse.ok || data.error || !data.access_token) {
        return new Response(JSON.stringify({
          error: data.error || "github_token_exchange_failed",
          error_description: data.error_description || ""
        }), { status: 502, headers: cors });
      }

      // Only return the short-lived OAuth result needed by the client.
      return new Response(JSON.stringify({
        access_token: data.access_token,
        token_type: data.token_type,
        scope: data.scope,
        expires_in: data.expires_in || null,
        refresh_token: data.refresh_token || null,
        refresh_token_expires_in: data.refresh_token_expires_in || null
      }), { status: 200, headers: cors });

    } catch (err) {
      return new Response(JSON.stringify({
        error: "worker_error",
        error_description: String(err && err.message || err)
      }), { status: 500, headers: cors });
    }
  }
};
