# i18n / Translations

## How to add a new language

1. Copy `_template.json` and rename it to your language code (e.g. `es.json`, `fr.json`, `de.json`, `pt-BR.json`)
2. Translate only the **values** (right side of the colon). Keep all **keys** exactly as they are
3. For plural forms, use `_plural` suffix (e.g. `entryCount` / `entryCount_plural`). The code picks based on count
4. Variables like `{count}` are replaced at runtime. Keep them in your translation
5. Submit a PR with your new file in this `locales/` directory

## Supported languages

| File | Language |
|------|----------|
| `en.json` | English (default) |

## Guidelines

- Keep translations concise. UI space is limited
- Use natural, everyday language. No technical jargon
- If a language has gendered forms, pick the most neutral/common phrasing
- Test your file is valid JSON before submitting (`jq . your-file.json`)
