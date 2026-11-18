# Archived: SCALO Barbers mentorship "book a call" page

This page was the live booking page at **book.buildwithscalo.com** until **2026-06-14**, and then at
**buildwithscalo.com/book** until **2026-11-18**, when `/book` was given to the new CONNECT booking system
(`buildwithscalo.com/book/call`).

Nothing was deleted. The page is intact in this folder, with its Meta Pixel and Calendly booking flow.

## Where it lives now
- In this folder: `book-barbers-archive/index.html` (edit it here like any other page).
- On the web: `buildwithscalo.com/book-barbers-archive`
- The folder is one level deep on purpose: the page loads its pictures with `../images/...`, so keep it one
  level below the site root or the pictures break.

## How to put it back at /book
In [`../vercel.json`](../vercel.json) delete the two `/book` rewrites that point at
`businessos.buildwithscalo.com`, rename this folder back to `book`, and deploy.
Anything that was sent to `/book/call` or `/book/r/...` by then stops working, so move those links first.
