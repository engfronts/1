# Engineering Frontiers Web Experience

Multi-page frontend for the Engineering Frontiers journal. Built with vanilla HTML, CSS, and JavaScript; no database or backend required.

## Pages
- `index.html` - Landing page with hero narrative plus full-size wordmark logo and editorial portraits for every board member photo provided.
- `journal.html` - Core facts, publisher information, and mission statement.
- `scope.html` - Seven editorial pillars.
- `articles.html` - Issues presented one by one, each with a dedicated cover and downloadable PDFs for every paper plus the entire issue.
- `contact.html` - Submission form plus office locations and contact info.

## Assets
- `assets/photos` stores the portraits for Yinzi Shao, Yuewen Gao, and Yutao Luo plus a placeholder headshot that covers editorial board members without official photography. The homepage grid uses these assets so every required photo appears on page one.
- `assets/papers` hosts six PDFs (five articles plus the full issue) that power the download buttons on the Articles page.

## Email Form (Serverless)
The contact form (with optional PDF upload) posts to [FormSubmit](https://formsubmit.co) via `https://formsubmit.co/engfront@yeah.net`. FormSubmit relays each submission straight to the inbox with:
- `_subject` to label messages in email clients.
- `_captcha=false` to avoid form verification friction.
- `_autoresponse` to send an automatic acknowledgement.

Switching to another mail gateway later only requires changing the `action` attribute in `contact.html`.

## Preview & Deployment
1. Open the `EngineeringFrontiers` folder.
2. Double-click any HTML file (or run a static server such as `npx serve .`).
3. Submit a test entry on `contact.html` to confirm email delivery to `engfront@yeah.net`.
4. Deploy by uploading the entire folder to any static host (OSS, COS, GitHub Pages, Netlify, Vercel, etc.).

## Customization Checklist
- Add new issues by duplicating the structure in `articles.html` (each issue should include an image and list of PDFs placed inside `assets/images` and `assets/papers`).
- Replace or expand photos inside `assets/photos`; the homepage grid automatically adapts.
- Adjust colors or spacing tokens inside `css/style.css` to evolve the visual direction while staying consistent.



