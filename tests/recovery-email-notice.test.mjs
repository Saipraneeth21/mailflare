import assert from "node:assert/strict";
import test from "node:test";
import { loadApp } from "./helpers/real-db.mjs";

const { app, newDatabase } = await loadApp("recovery-email-notice", `
	export { notifyPreviousRecoveryEmail } from "./src/lib/auth/recovery-changed-mail.ts";
`);

async function setup(t) {
	const fixture = await newDatabase(t, `
		INSERT INTO users (id, email, password_hash, name, role, created_at) VALUES ('a', 'admin@example.com', 'x', 'Admin', 'admin', 1);
		INSERT INTO domains (id, user_id, hostname, zone_id, status, sending_provider, sending_enabled, created_at) VALUES ('d', 'a', 'example.com', 'z', 'active', 'cloudflare', 1, 1);
		INSERT INTO mailboxes (id, user_id, domain_id, local_part, created_at) VALUES ('m', 'a', 'd', 'admin', 1);
	`);
	const sent = [];
	const env = { ...fixture.env, EMAIL: { send: async (message) => { sent.push(message); return { messageId: "1" }; } } };
	globalThis.__mailflareNodeEnv = env;
	t.after(() => { delete globalThis.__mailflareNodeEnv; });
	return { env, sent };
}
const user = { email: "u@example.com", resetEmail: "old@example.org" };

test("the previous recovery address is told, without the new one", async (t) => {
	const { env, sent } = await setup(t);
	await app.notifyPreviousRecoveryEmail(env, user, "new@example.net");
	assert.equal(sent.length, 1);
	const text = JSON.stringify(sent[0]);
	assert.match(text, /old@example\.org/);
	assert.match(text, /u@example\.com/);
	assert.doesNotMatch(text, /new@example\.net/);
	await app.notifyPreviousRecoveryEmail(env, user, null);
	assert.equal(sent.length, 2, "removing it counts too");
});

test("nothing is sent without a change or a previous address, and a mail failure is swallowed", async (t) => {
	const { env, sent } = await setup(t);
	await app.notifyPreviousRecoveryEmail(env, user, "OLD@example.org ");
	await app.notifyPreviousRecoveryEmail(env, { ...user, resetEmail: null }, "new@example.net");
	assert.equal(sent.length, 0);
	env.EMAIL.send = async () => { throw new Error("down"); };
	await app.notifyPreviousRecoveryEmail(env, user, "new@example.net");
});
