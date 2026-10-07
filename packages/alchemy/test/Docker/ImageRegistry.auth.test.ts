import { assert, describe, expect, it } from "alchemy-test";
import * as Effect from "effect/Effect";
import * as HttpClient from "effect/http/HttpClient";
import * as HttpClientResponse from "effect/http/HttpClientResponse";
import * as Redacted from "effect/Redacted";
import * as Result from "effect/Result";
import { resolveImageManifest } from "@/Docker/ImageRegistry";

const digest = `sha256:${"a".repeat(64)}`;

describe("registry token hosts", { tags: ["unit", "provider:docker", "local"] }, () => {
  for (const [server, realm] of [
    ["720cz3mljc.registry.depot.dev", "https://api.depot.dev"],
    ["registry.depot.dev", "https://api.depot.dev"],
    ["docker.io", "https://auth.docker.io"],
    ["registry.example", "https://registry.example"],
  ]) {
    it.effect(`authenticates ${server} through ${realm}`, () =>
      Effect.gen(function* () {
        const requests: Array<{ url: string; authorization?: string }> = [];
        const client = HttpClient.make((request, url) =>
          Effect.sync(() => {
            requests.push({ url: url.toString(), authorization: request.headers.authorization });
            if (request.method === "GET") {
              expect(request.headers.authorization).toBe("Basic eC10b2tlbjpyZWdpc3RyeS1zZWNyZXQ=");
              return HttpClientResponse.fromWeb(request, Response.json({ token: "scoped-token" }));
            }
            if (request.headers.authorization === "Bearer scoped-token") {
              return HttpClientResponse.fromWeb(
                request,
                new Response(null, {
                  headers: { "docker-content-digest": digest },
                }),
              );
            }
            return HttpClientResponse.fromWeb(
              request,
              new Response(null, {
                status: 401,
                headers: {
                  "www-authenticate": `Bearer realm="${realm}/auth/registry/token",service="${server}"`,
                },
              }),
            );
          }),
        );
        const image = yield* resolveImageManifest(`${server}/bodyiq/app:input-hash`, {
          server,
          username: "x-token",
          password: Redacted.make("registry-secret"),
        }).pipe(Effect.provideService(HttpClient.HttpClient, client));
        expect(image.ref).toBe(`${server}/bodyiq/app@${digest}`);
        expect(requests).toHaveLength(3);
        const tokenRequest = new URL(requests[1].url);
        expect(tokenRequest.searchParams.get("service")).toBe(server);
        expect(tokenRequest.searchParams.get("scope")).toBe("repository:bodyiq/app:pull");
      }),
    );
  }

  for (const [server, realm] of [
    ["720cz3mljc.registry.depot.dev", "https://attacker.example/token"],
    ["registry.depot.dev.attacker.example", "https://api.depot.dev/auth/registry/token"],
    ["registry.example", "https://api.depot.dev/auth/registry/token"],
    ["720cz3mljc.registry.depot.dev", "http://api.depot.dev/auth/registry/token"],
  ]) {
    it.effect(`does not forward ${server} credentials to ${realm}`, () =>
      Effect.gen(function* () {
        let requests = 0;
        const client = HttpClient.make((request) =>
          Effect.sync(() => {
            requests++;
            return HttpClientResponse.fromWeb(
              request,
              new Response(null, {
                status: 401,
                headers: { "www-authenticate": `Bearer realm="${realm}"` },
              }),
            );
          }),
        );
        const result = yield* resolveImageManifest(`${server}/bodyiq/app:input-hash`, {
          server,
          username: "x-token",
          password: Redacted.make("registry-secret"),
        }).pipe(Effect.provideService(HttpClient.HttpClient, client), Effect.result);
        assert(Result.isFailure(result));
        expect(result.failure.reason).toBe("AuthenticationFailed");
        expect(requests).toBe(1);
      }),
    );
  }
});
