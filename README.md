# Improved WordPress Site Health: hardening posture

A prototype from a WordCamp working group on hardening WordPress from the moment it is installed. The idea is a firewall for features: everything closes by default and you open things deliberately, with Site Health telling you what is still exposed and what the hosting environment gets wrong.

It ships as a single must-use plugin, `hardening-posture.php`. It is a spike, not a release: no tests, no settings API, no translations, and the code is meant to be read and argued about rather than shipped as is.

## What it adds

### A Hardening tab in Site Health

Tools → Site Health → Hardening.

**Postures.** Pick one of three:

| Posture | Meaning |
|---|---|
| Locked | Every feature closes. You open the ones you need, one by one. |
| Standard | What WordPress ships with. Only your own switches apply. |
| Open | Everything open. For a development site. |

**Dials.** Eleven features, each with an Open/Closed switch, the state it is in right now, a short explanation of what closing it protects, a link to the official documentation, and the `wp-config.php` line that makes it permanent:

- Theme and plugin file editor (`DISALLOW_FILE_EDIT`)
- Installing plugins, themes and updates from the dashboard (`DISALLOW_FILE_MODS`)
- Unfiltered HTML for editors and admins (`DISALLOW_UNFILTERED_HTML`)
- XML-RPC endpoint
- Application passwords
- Unauthenticated REST user listing (`/wp/v2/users`)
- Open user registration
- Outbound HTTP to arbitrary hosts (`WP_HTTP_BLOCK_EXTERNAL`)
- Dashboard reachable over plain HTTP (`FORCE_SSL_ADMIN`)
- PHP errors displayed to visitors
- Pingbacks and trackbacks on new posts

A switch records an override only where it differs from the posture's default, so changing posture later re-applies that posture's defaults instead of frozen choices. A dial whose constant is already set in `wp-config.php` is pinned: its switch is disabled and the row says which constant owns it.

Two dials stay open under Locked unless you close them yourself, because closing them has side effects: dashboard installs (it also stops automatic updates) and outbound HTTP (it breaks update checks until `WP_ACCESSIBLE_HOSTS` lists what you need). Plain HTTP admin also stays open on a site that is not served over HTTPS, since forcing SSL there locks you out.

**Drift.** Anything that is still open although it was switched closed is marked as drift on the row and reported as a critical item on the Status tab.

### Nine new Site Health status tests

| Test | What it looks at |
|---|---|
| Hardening posture | Dials that drift from the posture you chose |
| Address bar matches the site address | The host and scheme the browser used against the raw `home` and `siteurl` options; a different host is critical, a different scheme only is recommended |
| PHP process confinement | `open_basedir`, `disable_functions`, `allow_url_include`, `expose_php`, whether PHP can write to core directories, the built-in dev server |
| Configuration hygiene | `WP_ENVIRONMENT_TYPE`, secret keys, the `wp_` table prefix, a user named `admin`, `wp-config.php` inside the web root, leftover `readme.html` and `wp-config-sample.php`, the file editor |
| Database user privileges | `SHOW GRANTS`: all privileges on every database, `FILE`, `SUPER`, `GRANT OPTION`, `@%` hosts, databases reached over the network |
| Plugins outside the directory | Plugins that WordPress.org does not track, so no update or closure notices reach the site; reports "could not check" instead of guessing when update data is missing |
| PHP execution in uploads | Writes a probe file into `wp-content/uploads`, fetches it, deletes it |
| Exposed files | `readme.html`, `license.txt`, `.env`, `wp-config.php` backups, `debug.log`, `.git` and directory listings reachable over HTTP, each matched on its own signature |

The three tests that request the site over HTTP (uploads probe, exposed files, server hygiene) are registered as async tests with a REST endpoint under `hp/v1/tests/`, the same way core runs its loopback test, so the Status tab never waits on them. The weekly cron calls them directly.
| Web server hygiene | `Server` and `X-Powered-By` banners, missing security headers, `Strict-Transport-Security` on HTTPS sites, plain-HTTP sites |

### Security releases reported as critical

Core currently reports a pending update as *recommended* with a *Performance* badge when a newer major branch exists, even if there is also a maintenance and security release for the branch you are on. The plugin filters `site_status_test_result` so that a pending release in your own `major.minor` branch is reported as *critical* with a *Security* badge, pointing to the update screen.

## Install

Copy `hardening-posture.php` into `wp-content/mu-plugins/` (create the folder if it does not exist). Must-use plugins load automatically and cannot be deactivated from the dashboard; delete the file to remove it.

It has to be a must-use plugin: the constants it defines are read by core before normal plugins load, so a regular plugin would be too late for `DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`, `DISALLOW_UNFILTERED_HTML`, `WP_HTTP_BLOCK_EXTERNAL` and `FORCE_SSL_ADMIN`.

Options used: `hp_posture` (string) and `hp_states` (array of overrides). Delete both to reset.

## How enforcement works

At load the plugin walks the dials that should be closed. For the constant-backed ones it defines the constant unless `wp-config.php` already did. For the rest it hooks filters: `xmlrpc_enabled` plus an early 403 on XML-RPC requests, `wp_is_application_passwords_available`, `rest_pre_dispatch` for unauthenticated user listing, `option_users_can_register`, `option_default_ping_status` and the `pingback.ping` XML-RPC method, and `display_errors` through `ini_set`.

The plugin only ever closes things. It never opens a feature that core, `wp-config.php` or the server keeps closed, which is why a dial can show "Closed" while its switch says "Open".

## Not in this prototype yet

- Running at install time, so the constants land in `wp-config.php` while the installer still owns that file.
- History, so the dashboard can say what changed since the last weekly run.
- An export of host-level findings for the hosting provider.
- A core patch. The same switches would set the constants' defaults directly in core, which is cleaner than defining them from a plugin.

## License

GPL-2.0-or-later, like WordPress.
