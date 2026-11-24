# Changes in this fork

This is a modified version of [Mailflare](https://github.com/hieunc229/mailflare), under the same licence
(AGPL-3.0, see LICENSE). Based on upstream commit `dd5df0d`. Modified on 2026-11-24:

- Two-factor codes on step-up and on settings changes now count towards the account's attempt limit, as
  they already did at sign-in.
- Sign-in rate limits group IPv6 clients by /64.
- The previous recovery address is told when it is replaced or removed.
- Updated `mailauth`, `smtp-server`, `sharp`, `undici`, `wrangler` and others with known vulnerabilities.

If you run this for other people, AGPL section 13 requires offering them this source.
