# Companion UI requirements

- Keep the companion minimalist, with a white background, dark text, and Gowun Batang. The user clarified that text must remain readable.
- Ask the user before introducing or changing any on-screen wording, including headings, labels, placeholders, accessibility labels, loading states, errors, confirmations, and browser titles. Approval is required before displaying it on a page or preview.
- `ui_copy.json` contains the exact wording explicitly approved by the user on 2026-10-22. Reuse it through the `ui` template global and the JSON copy block; do not introduce separate literals in templates or scripts.
- Do not display arbitrary server errors, generated status messages, or explanatory paragraphs. Show only an approved error label for failed requests.
- Account rows show website domains only. Do not display Telegram IDs, usernames, secret masks, task prompts, task IDs, or other unnecessary user information. Internal identifiers needed by forms are not display content.
- Keep pages light: local CSS and JavaScript, a local font with `font-display: swap`, no runtime CSS framework, no decorative animation, no UI framework dependency.
