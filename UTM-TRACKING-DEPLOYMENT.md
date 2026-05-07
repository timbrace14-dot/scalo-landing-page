# UTM Tracking — Deployment Steps

Three things go live in this order. Total time: ~5 minutes.

---

## 1. Run the SQL in Supabase

This creates the new `utm_clicks` table that stores every page visit.

1. Open your Supabase project: <https://supabase.com/dashboard/project/kadgzthwuzzjwxxcbgzi/sql/new>
2. Open the file `utm-tracking-schema.sql` (in the SCALO Landing page folder).
3. Paste the entire contents into the SQL Editor.
4. Hit **Run**.
5. You should see "Success. No rows returned." That's correct.

Verify it worked: navigate to **Table Editor** in the left sidebar, you should now see `utm_clicks` listed alongside `clients` and any other existing tables.

---

## 2. Deploy the landing page

The landing page now writes a row to `utm_clicks` every time someone visits with a UTM-tagged link (or any visit at all, anonymously).

```bash
cd "/Users/timbrace/Desktop/SCALO Landing page"
git add index.html utm-tracking-schema.sql UTM-TRACKING-DEPLOYMENT.md
git commit -m "Add anonymous UTM pageview tracking"
git push
```

Vercel auto-deploys on push. Wait ~30 seconds, then test:

1. Visit `https://join.buildwithscalo.com/?utm_source=tbh&utm_medium=dms`
2. Open browser DevTools → Console. Look for `[Pageview] Tracked OK`.
3. In Supabase Table Editor, open `utm_clicks` — your visit should be in there with `utm_source = "tbh"`, `utm_medium = "dms"`.

---

## 3. Deploy the Business OS

The Business OS Link Tracker dashboard now shows visits, leads, conversion rate, and a top-source card — with a Today / This Week / Month-to-Date / All Time toggle.

The BOS lives on your **LaCie external drive** at `/Volumes/LaCie/SCALO Buisiness OS/scalo-business-os/`. Make sure the drive is plugged in.

```bash
cd "/Volumes/LaCie/SCALO Buisiness OS/scalo-business-os"
# however you normally deploy this — git push, vercel deploy, etc.
```

No config required. The BOS already has the same Supabase credentials hardcoded as the landing page, so the moment the SQL is in place and the new BOS is deployed, the dashboard reads live data.

---

## The 5 finalised links (use these exact ones)

```
YOUTUBE
https://join.buildwithscalo.com/?utm_source=youtube&utm_medium=description

INSTAGRAM @timbracehair — DMs
https://join.buildwithscalo.com/?utm_source=tbh&utm_medium=dms

INSTAGRAM @scalewithtim — DMs
https://join.buildwithscalo.com/?utm_source=swt&utm_medium=dms

INSTAGRAM @timbracehair — Stories
https://join.buildwithscalo.com/?utm_source=tbh&utm_medium=stories

INSTAGRAM @scalewithtim — Stories
https://join.buildwithscalo.com/?utm_source=swt&utm_medium=stories
```

The team must use the exact link for each surface. No edits, no extra params, no removing the `?utm_source=...` bit.

---

## What gets tracked

For every visit to `join.buildwithscalo.com`, a row goes into `utm_clicks` with:

- `visited_at` — exact timestamp
- `utm_source`, `utm_medium`, `utm_campaign`, `utm_content`
- `visitor_id` — anonymous random ID stored in localStorage, lets you spot returning visitors
- `referrer` — where they clicked from (useful for direct/organic traffic)
- `landing_path` — the URL they hit (useful if you add more pages later)
- `device` — `mobile` or `desktop`
- `is_bot` — true if the user agent looks like a crawler (filtered out of dashboard)

---

## What the dashboard shows

Open **Business OS → Sidebar → Link Tracker**.

**Top row of cards** (driven by the time period toggle):
- Visits — total pageviews in selected period
- Leads — total opt-ins in selected period
- Conversion — leads ÷ visits, as a percentage
- Top Source — which source pulled the most traffic

**Per-brand cards** (Tim Brace Hair / Scale With Tim / YouTube):
- Brand-level visits, leads, conversion %
- Per-channel breakdown (Stories vs DMs, etc.) with a horizontal bar showing relative volume

Click any of the four time buttons to instantly re-filter everything. No reload needed.

---

## Things to know

- **Bot traffic is filtered.** Crawler/spider/bot user agents are tagged `is_bot = true` and excluded from the dashboard.
- **Reloads in the same session don't double-count.** A `sessionStorage` flag keeps it to one row per session.
- **The first visitor ID created in a browser persists.** Same visitor across multiple sessions = same ID, so you can later add "unique visitors" metrics if you want.
- **Direct traffic** (no UTM) still gets logged — `utm_source` will be `null`. The dashboard groups it under "Direct".
- **Leads table is untouched.** The existing opt-in flow continues to work the same way.
- **No personal data is stored.** No emails, no IPs, just the anonymous visitor ID + UTM tags.

---

## Quick troubleshoot

**Dashboard says "Loading…" forever:** Supabase auth session probably expired. Refresh the BOS page. If still broken, log out and back in.

**Visits not appearing for new clicks:** Check the browser console on the landing page for `[Pageview] Track failed` — usually means the SQL hasn't been run yet, or RLS policies are wrong.

**A visit is showing under the wrong brand:** Someone shared the wrong UTM link. Audit which channel is using a mismatched URL and re-share the correct one.
