# Life Manager — Telegram bot + Mini App + AI (Claude)

## Ishga tushirish
1. @BotFather → /newbot → token oling.
2. Ovoz uchun Aisha API kaliti: https://voicelab.uz/app (narx/balansni tekshiring: xizmat pullik bo'lishi mumkin).
3. Serverga ffmpeg o'rnating (ilova ichidagi mikrofon uchun): `sudo apt install ffmpeg`
4. `cp .env.example .env` va to'ldiring.
5. `pip install -r requirements.txt`
6. `uvicorn app:app --host 0.0.0.0 --port 8000`
7. HTTPS kerak: sinash uchun `cloudflared tunnel --url http://localhost:8000`,
   chiqqan https manzilni `WEBAPP_URL` ga yozib, qayta ishga tushiring.
8. @BotFather → Bot Settings → Menu Button → shu URL.

Brauzerda sinash: `.env` da `DEV=1`, so'ng http://localhost:8000

## PIN
- Birinchi ochilishda 4 xonali PIN o'rnatiladi (serverda scrypt bilan xeshlanadi).
- 5 ta xato urinishdan keyin 5 daqiqa bloklanadi (keyingi bloklar uzayib boradi).
- 60 soniya fonda tursa yoki 30 daqiqadan keyin qayta so'raydi.
- Unutilsa: botga `/resetpin`. PIN bilan birga barcha ma'lumot o'chadi.

## Ovoz
- Eng ishonchli: botga ovozli xabar yuborish (Telegram o'zi yozadi, server Aisha orqali matnga aylantiradi).
- Ilova ichida: mikrofon tugmasi (Telegram versiyasiga qarab ishlamasligi mumkin).
- Bot chatida AI faqat yozadi (xarajat/reja qo'shadi). Hisobotni ko'rish faqat PIN bilan ilovada.
