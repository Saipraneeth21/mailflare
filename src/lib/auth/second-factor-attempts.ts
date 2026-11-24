import { and, count, eq, gt } from "drizzle-orm";
import { getDb } from "@/db";
import { auditLogs } from "@/db/schema";
import { newId } from "@/lib/ids";
import { getAuthActivityMetadata } from "./activity";
import { verifySecondFactor } from "./mfa";

/**
 * Wrong second-factor codes are limited per account, across every IP and login
 * challenge, so a known password does not leave the six-digit code to the
 * per-IP login limiter alone. Each attempt is logged before its code is
 * checked, so parallel guesses count too; a correct code removes its own
 * entry, and wrong ones stay in the audit log.
 */
const MAX_FAILED_ATTEMPTS = 5;
const WINDOW_MINUTES = 15;
const FAILED_ACTION = "auth.second_factor_failed";

/** Returns an attempt id to clear once the code is correct, or null when the account is out of attempts. */
export async function reserveSecondFactorAttempt(env: CloudflareEnv, userId: string, request?: Request): Promise<string | null> {
	const db = getDb(env);
	const id = newId("aud");
	await db.insert(auditLogs).values({
		id,
		targetUserId: userId,
		action: FAILED_ACTION,
		metadata: request ? JSON.stringify(getAuthActivityMetadata(request)) : null,
	});
	const since = new Date(Date.now() - WINDOW_MINUTES * 60 * 1000);
	const [row] = await db
		.select({ attempts: count() })
		.from(auditLogs)
		.where(and(eq(auditLogs.targetUserId, userId), eq(auditLogs.action, FAILED_ACTION), gt(auditLogs.createdAt, since)));
	if ((row?.attempts ?? 0) <= MAX_FAILED_ATTEMPTS) return id;
	await clearSecondFactorAttempt(env, id);
	return null;
}

/** Check a code within the account's attempt limit. "limited" means it was not checked at all. */
export async function verifyLimitedSecondFactor(
	env: CloudflareEnv,
	user: Parameters<typeof verifySecondFactor>[1],
	code: string,
	request?: Request,
): Promise<"ok" | "mismatch" | "limited"> {
	const attempt = await reserveSecondFactorAttempt(env, user.id, request);
	if (!attempt) return "limited";
	if (!(await verifySecondFactor(env, user, code))) return "mismatch";
	await clearSecondFactorAttempt(env, attempt);
	return "ok";
}

/** A correct code is not a failed attempt. */
export async function clearSecondFactorAttempt(env: CloudflareEnv, attemptId: string): Promise<void> {
	await getDb(env).delete(auditLogs).where(eq(auditLogs.id, attemptId));
}
