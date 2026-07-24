import asyncio
import logging
import os
from pathlib import Path

import yaml
from dotenv import load_dotenv
from formatter import format_reply
from telegram import Update
from telegram.ext import (
    Application, CommandHandler, MessageHandler, filters, ContextTypes
)

from agent import inspect_file, inspect_text
from links import extract_urls
 
load_dotenv()
 
logging.basicConfig(
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    level=logging.INFO,
)
log = logging.getLogger(__name__)
 
# Telegram's Bot API cannot download files larger than 20 MB.
MAX_TELEGRAM_FILE_MB = 20
 
 
 
START_INTRO = (
    "សួស្តី! សូមបញ្ជូនឯកសារ ឬសារដែលមានតំណ មកខ្ញុំ ខ្ញុំនឹងពិនិត្យវាឲ្យអ្នក។\n"
    "Hello! Forward me a file, or a message with a link, and I will check it.\n"
    "\n"
    "⚠️ ចំណាំ៖ ចម្លើយរបស់ខ្ញុំមិនត្រឹមត្រូវ ១០០% ទេ។ សូមប្រុងប្រយ័ត្នជានិច្ច។\n"
    "⚠️ Note: my answer is not 100% accurate. Always stay careful and use "
    "your own judgement."
)

# Header that introduces the embedded "already been scammed" help section.
_HELP_HEADER = (
    "─────────────\n"
    "បើអ្នកបានបាត់បង់លុយ ឬបានបោកប្រាស់រួចហើយ៖\n"
    "If you have already lost money or been scammed:\n"
)


# ⚠️  VERIFY BEFORE DEPLOYMENT: the reporting channel named below (the
#     Anti-Cyber Crime Department) and the bank hotlines pulled from
#     data/cambodian_apps.yaml must both be confirmed against official
#     sources. A wrong emergency number sends a distressed victim in the
#     wrong direction and costs them time they do not have.
_REF = yaml.safe_load(
    (Path(__file__).parent / "data" / "cambodian_apps.yaml").read_text(encoding="utf-8")
)


def _hotline_lines() -> str:
    """One '• Name: number' line per institution that has a hotline.

    Built from the reference file so the numbers live in exactly one place.
    Institutions with no `hotline` field are simply omitted.
    """
    lines = [
        f"  • {inst['name']}: {inst['hotline']}"
        for inst in _REF["institutions"]
        if inst.get("hotline")
    ]
    return "\n".join(lines)


def _help_message() -> str:
    hotlines = _hotline_lines()
    bank_block_km = (
        f"\n{hotlines}\n" if hotlines else
        "\n(សូមរកលេខទូរស័ព្ទផ្លូវការរបស់ធនាគារនៅខាងក្រោយប័ណ្ណ ATM ឬក្នុងកម្មវិធីធនាគារ។)\n"
    )
    bank_block_en = (
        "" if hotlines else
        "(Find your bank's official number on the back of your ATM card or in "
        "its app.)\n"
    )
    return (
        # --- Khmer ---
        "បើអ្នកបានបាត់បង់លុយ ឬបានផ្តល់ព័ត៌មានទៅឲ្យអ្នកបោកប្រាស់ សូមកុំបន្ទោសខ្លួនឯង។ "
        "រឿងនេះកើតឡើងចំពោះមនុស្សដែលប្រុងប្រយ័ត្នផងដែរ។\n"
        "\n"
        "១. ទូរស័ព្ទទៅធនាគាររបស់អ្នកឥឡូវនេះ។ បើអ្នករាយការណ៍លឿន ជួនកាលធនាគារអាចបញ្ឈប់ការផ្ទេរប្រាក់បាន។"
        f"{bank_block_km}"
        "\n"
        "២. ថតរូបអេក្រង់ និងរក្សាទុកសារ លេខគណនី និងព័ត៌មានទាំងអស់ ទុកជាភស្តុតាង។\n"
        "\n"
        "៣. រាយការណ៍ទៅប៉ូលិស ឬនាយកដ្ឋានប្រឆាំងបទល្មើសបច្ចេកវិទ្យា (Anti-Cyber Crime Department)។\n"
        "\n"
        "ខ្ញុំមិនអាចធានាថាលុយនឹងអាចយកមកវិញបានទេ ប៉ុន្តែសកម្មភាពលឿននឹងជួយបានច្រើនបំផុត។\n"
        "\n"
        "─────────────\n"
        # --- English ---
        "If you lost money or gave information to a scammer, do not blame "
        "yourself. This happens to careful people too.\n"
        "\n"
        "1. Call your bank now. If you report quickly, the bank can sometimes "
        "stop the transfer.\n"
        f"{bank_block_en}"
        "\n"
        "2. Take screenshots and keep the messages, account numbers, and all "
        "details as evidence.\n"
        "\n"
        "3. Report it to the police or the Anti-Cyber Crime Department.\n"
        "\n"
        "I cannot promise the money can be recovered, but acting fast helps "
        "the most."
    )


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    # The scam-recovery help is embedded directly in the greeting so the user
    # sees everything in one message — nothing to tap and nothing to type.
    await update.message.reply_text(
        f"{START_INTRO}\n\n{_HELP_HEADER}\n{_help_message()}"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text(_help_message())
 
 
async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    text = update.message.text or ""
    log.info("Text from %s (%d chars)", update.effective_user.id, len(text))

    # Only messages that actually contain a link can be checked. A plain chat
    # message has nothing to analyse yet.
    if not extract_urls(text):
        await update.message.reply_text(
            "Send me a file, or a message with a link in it, and I will check it."
        )
        return

    notice = await update.message.reply_text("Checking the link... one moment.")

    try:
        result = await asyncio.to_thread(
            inspect_text, text, update.effective_user.id,
        )
    except Exception:
        log.exception("Link analysis failed")
        await notice.edit_text(
            "Sorry, I could not check that message. Please try again."
        )
        return

    await notice.edit_text(format_reply(result))
 
 
async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    doc = update.message.document
    caption = update.message.caption or ""
 
    log.info("File from %s: %s (%s bytes, %s)",
             update.effective_user.id, doc.file_name, doc.file_size, doc.mime_type)
 
    # --- guard: too large for the Bot API to fetch ---
    if doc.file_size and doc.file_size > MAX_TELEGRAM_FILE_MB * 1024 * 1024:
        await update.message.reply_text(
            f"That file is too large for me to check "
            f"(limit {MAX_TELEGRAM_FILE_MB} MB)."
        )
        return
 
    notice = await update.message.reply_text("Checking... please wait a moment.")

    try:
        # Ask Telegram where the file lives. No bytes move yet — the agent
        # decides whether a download is actually necessary. This call can fail
        # on a transient Telegram/network error, so it must be inside the try:
        # otherwise the exception escapes and the "Checking..." notice above is
        # left hanging forever with no answer to the user.
        tg_file = await context.bot.get_file(doc.file_id)
        file_url = tg_file.file_path          # a full https URL

        # asyncio.to_thread keeps the blocking crew off the event loop, so one
        # slow analysis does not freeze the bot for every other user.
        result = await asyncio.to_thread(
            inspect_file,
            doc.file_name or "unknown",
            caption,
            file_url,
            update.effective_user.id,
        )
    except Exception:
        log.exception("Analysis failed")
        await notice.edit_text(
            "Sorry, I could not check that file. Please try again."
        )
        return
 
    await notice.edit_text(format_reply(result))
 
 
def main() -> None:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN missing. Check your .env file.")
 
    app = Application.builder().token(token).build()
 
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
 
    log.info("Bot starting...")
    app.run_polling()
 
 
if __name__ == "__main__":
    main()
 