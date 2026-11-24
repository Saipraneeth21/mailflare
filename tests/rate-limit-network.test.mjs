import assert from "node:assert/strict";
import test from "node:test";
import { loadApp } from "./helpers/real-db.mjs";

const { app } = await loadApp("rate-limit-network", `
	export { allowLoginAttempt, rateLimitNetwork } from "./src/lib/auth/rate-limit.ts";
`);

test("IPv6 clients are limited per /64, everything else per address", () => {
	const same = ["2001:db8:1:2::1", "2001:0DB8:0001:0002:ffff:ffff:ffff:ffff", "2001:db8:1:2:a:b:c:d%eth0"];
	for (const ip of same) assert.equal(app.rateLimitNetwork(ip), "2001:db8:1:2::/64", ip);
	assert.notEqual(app.rateLimitNetwork("2001:db8:1:3::1"), "2001:db8:1:2::/64");
	assert.equal(app.rateLimitNetwork("::1"), "0:0:0:0::/64");
	assert.equal(app.rateLimitNetwork("203.0.113.7"), "203.0.113.7");
	assert.equal(app.rateLimitNetwork("::ffff:203.0.113.7"), "203.0.113.7");
	for (const odd of ["unknown", "1:2:3", "2001:db8::1::2", "2001:db8:1:2:3:4:5:6:7", "zz::1", ""]) assert.equal(app.rateLimitNetwork(odd), odd);
});

test("the login limiter sees the network", async () => {
	const keys = [];
	const env = { LOGIN_RATE_LIMIT: { limit: async ({ key }) => (keys.push(key), { success: true }) } };
	for (const ip of ["2001:db8::1", "2001:db8::2", "198.51.100.4"]) {
		await app.allowLoginAttempt(env, new Request("http://localhost/", { headers: { "x-mailflare-client-ip": ip } }));
	}
	assert.deepEqual(keys, ["2001:db8:0:0::/64", "2001:db8:0:0::/64", "198.51.100.4"]);
});
