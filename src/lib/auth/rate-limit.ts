import { getClientIp } from "./client-ip";

/**
 * Key rate limits by the resolved client IP. Without a per-client key every
 * visitor lands in one shared "unknown" bucket and scanners can lock out
 * legitimate logins; trusting raw forwarding headers here would be worse —
 * a client could rotate them to leave the bucket entirely.
 */
function clientRateLimitKey(request: Request): string {
	return rateLimitNetwork(getClientIp(request) ?? "unknown");
}

/**
 * One IPv6 customer usually holds a whole /64, so a limit per full address could be dodged by rotating it.
 * IPv4 (also in its IPv6-mapped form) and anything unparseable stay as they are.
 */
export function rateLimitNetwork(ip: string): string {
	const address = ip.split("%", 1)[0].toLowerCase();
	const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(address);
	if (mapped) return mapped[1];
	if (!/^[0-9a-f:]+(?:\d{1,3}(?:\.\d{1,3}){3})?$/.test(address) || !address.includes(":")) return ip;
	const halves = address.split("::");
	if (halves.length > 2) return ip;
	const groups = (part: string) => (part ? part.split(":") : []).flatMap((group) => (group.includes(".") ? ["0", "0"] : [group]));
	const head = groups(halves[0]);
	const tail = halves.length === 2 ? groups(halves[1]) : [];
	const missing = 8 - head.length - tail.length;
	if (halves.length === 2 ? missing < 1 : missing !== 0) return ip;
	const all = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
	if (all.some((group) => !/^[0-9a-f]{1,4}$/.test(group))) return ip;
	return `${all.slice(0, 4).map((group) => Number.parseInt(group, 16).toString(16)).join(":")}::/64`;
}

/** Mobile sign-ins have their own, stricter budget (they skip Turnstile). */
export async function allowDeviceLoginAttempt(env: CloudflareEnv, request: Request): Promise<boolean> {
	const limiter = env.DEVICE_LOGIN_RATE_LIMIT ?? env.LOGIN_RATE_LIMIT;
	if (!limiter) return true;
	try {
		return (await limiter.limit({ key: `device:${clientRateLimitKey(request)}` })).success;
	} catch (error) {
		console.warn("Device login rate limiter unavailable", error);
		return true;
	}
}

/** Public booking submissions send mail from the host's address, so they get a per-client budget of their own. */
export async function allowBookingAttempt(env: CloudflareEnv, request: Request): Promise<boolean> {
	if (!env.LOGIN_RATE_LIMIT) return true;
	try {
		return (await env.LOGIN_RATE_LIMIT.limit({ key: `booking:${clientRateLimitKey(request)}` })).success;
	} catch (error) {
		console.warn("Booking rate limiter unavailable", error);
		return true;
	}
}

export async function allowLoginAttempt(env: CloudflareEnv, request: Request): Promise<boolean> {
	if (!env.LOGIN_RATE_LIMIT) return true;
	try {
		const outcome = await env.LOGIN_RATE_LIMIT.limit({ key: clientRateLimitKey(request) });
		return outcome.success;
	} catch (error) {
		console.warn("Login rate limiter unavailable", error);
		return true;
	}
}
