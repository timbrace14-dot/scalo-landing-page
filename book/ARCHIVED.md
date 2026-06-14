# Archived: SCALO Barbers mentorship "book a call" page

This `book/index.html` was the live booking page at **book.buildwithscalo.com**
until **2026-06-14**, when the subdomain was repointed to the new SCALO Online
founders page at `/book-a-call/`.

It is the **SCALO Barbers mentorship book-a-call page** (the old funnel). It has
not been deleted — it stays here, fully intact with its Meta Pixel and Calendly
booking flow, so it can be brought back live at any time.

## How to put it back live
In [`../vercel.json`](../vercel.json), change the two `book.buildwithscalo.com`
rewrite destinations back from `/book-a-call/index.html` to `/book/index.html`,
then deploy. That's the only change needed.

It also remains directly viewable at `buildwithscalo.com/book` and in git history.
