import { getBranding } from "@/lib/branding/service";
import { sendSystemEmail } from "@/lib/email/system-mail";
import { escapeHtml } from "./password-reset-utils";

/**
 * Tell the previous recovery address that it no longer is one, so an owner notices a change they did not
 * make. Best effort: a mail problem must not undo or fail the change. It names no new address, since the
 * previous one may belong to somebody else by now.
 */
export async function notifyPreviousRecoveryEmail(env: CloudflareEnv, user: { email: string; resetEmail: string | null }, next: string | null | undefined): Promise<void> {
	const previous = user.resetEmail?.trim();
	if (!previous || previous.toLowerCase() === (next ?? "").trim().toLowerCase()) return;
	try {
		const { appName } = await getBranding(env);
		const lines = [
			`The recovery email of the ${appName} account ${user.email} was changed. Password reset links no longer come to this address.`,
			"If this wasn't you or someone you trust, sign in, change the password and check the recovery email, or ask your administrator.",
		];
		await sendSystemEmail(env, {
			to: previous,
			subject: `${appName}: recovery email changed`,
			text: lines.join("\n\n"),
			html: lines.map((line) => `<p>${escapeHtml(line)}</p>`).join(""),
		});
	} catch (error) {
		console.error("Could not notify the previous recovery address", error);
	}
}
