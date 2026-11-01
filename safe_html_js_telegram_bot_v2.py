#!/usr/bin/env python3
"""
Safe HTML/JS cleaner Telegram bot.

Features:
- Cleans HTML entities and formats HTML.
- Formats JavaScript without executing it.
- Extracts inline scripts into separate .js files.
- Reports common obfuscation/protection indicators.
- Does NOT crack passwords, proprietary encryption, licensing, or access controls.
"""

import os
import re
import html
import tempfile
from pathlib import Path

from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

from bs4 import BeautifulSoup, Comment
import jsbeautifier


MAX_FILE_SIZE = 15 * 1024 * 1024


def beautify_js(source: str) -> str:
    options = jsbeautifier.default_options()
    options.indent_size = 2
    options.preserve_newlines = True
    options.max_preserve_newlines = 2
    return jsbeautifier.beautify(source, options)


def inspect_obfuscation(source: str) -> list[str]:
    findings = []
    checks = [
        (r"\batob\s*\(", "Base64 decoding call (atob)"),
        (r"\bfromCharCode\s*\(", "Character-code reconstruction"),
        (r"\beval\s*\(", "Dynamic code execution call (eval)"),
        (r"\bFunction\s*\(", "Dynamic Function constructor"),
        (r"\\x[0-9a-fA-F]{2}", "Hex-escaped string characters"),
        (r"\\u[0-9a-fA-F]{4}", "Unicode-escaped string characters"),
        (r"\b_0x[0-9a-fA-F]+\b", "Obfuscator-style hexadecimal identifiers"),
        (r"\bwhile\s*\(\s*!!\s*\[\s*\]", "Control-flow obfuscation pattern"),
    ]
    for pattern, label in checks:
        if re.search(pattern, source):
            findings.append(label)
    if not findings:
        findings.append("No common obfuscation indicators detected")
    return findings


def process_html(raw: str, original_name: str, out_dir: Path):
    # Decode HTML entities and normalize markup; never run embedded scripts.
    raw = html.unescape(raw)
    soup = BeautifulSoup(raw, "html.parser")

    # Remove comments only when they are ordinary HTML comments.
    # Conditional comments are retained.
    for node in soup.find_all(string=lambda value: isinstance(value, Comment)):
        if not re.match(r"\s*\[if\b", str(node), re.I):
            node.extract()

    scripts = []
    reports = []
    for index, tag in enumerate(soup.find_all("script"), start=1):
        script_text = tag.string if tag.string is not None else tag.get_text()
        src = tag.get("src")

        if script_text and script_text.strip():
            formatted = beautify_js(script_text)
            scripts.append((f"inline_script_{index}.js", formatted))
            reports.append(
                f"Inline script {index}: " + "; ".join(inspect_obfuscation(script_text))
            )
            # Keep script content in the HTML; only format its text.
            tag.clear()
            tag.append("\\n" + formatted + "\\n")

        elif src:
            reports.append(f"External script reference retained: {src}")

    pretty_html = soup.prettify(formatter="html")
    html_path = out_dir / f"{Path(original_name).stem}_cleaned.html"
    html_path.write_text(pretty_html, encoding="utf-8")

    script_paths = []
    for filename, content in scripts:
        path = out_dir / filename
        path.write_text(content, encoding="utf-8")
        script_paths.append(path)

    report_path = out_dir / "decode_report.txt"
    report_path.write_text(
        "SAFE STATIC ANALYSIS REPORT\\n"
        "===========================\\n"
        "The file was parsed and formatted without executing its JavaScript.\\n"
        "Formatting is not the same as decrypting or recovering original source.\\n\\n"
        + ("\\n".join(reports) if reports else "No inline scripts found.")
        + "\\n",
        encoding="utf-8",
    )
    return [html_path, *script_paths, report_path]


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "HTML/JS Safe Cleaner চালু আছে। .html, .htm, .js বা .txt ফাইল পাঠাও।\\n"
        "আমি HTML clean, JS beautify, inline script extract এবং obfuscation report দিতে পারি।\\n"
        "Password, proprietary encryption বা license protection crack করি না।"
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    name = doc.file_name or "uploaded_file.txt"
    suffix = Path(name).suffix.lower()

    if suffix not in {".html", ".htm", ".js", ".txt"}:
        await update.message.reply_text("শুধু .html, .htm, .js বা .txt ফাইল পাঠাও।")
        return

    if doc.file_size and doc.file_size > MAX_FILE_SIZE:
        await update.message.reply_text("ফাইলটি 15 MB-এর বেশি। ছোট ফাইল পাঠাও।")
        return

    tg_file = await context.bot.get_file(doc.file_id)

    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp)
        input_path = work / Path(name).name
        await tg_file.download_to_drive(custom_path=str(input_path))

        try:
            raw = input_path.read_text(encoding="utf-8", errors="replace")
            if suffix in {".html", ".htm"}:
                outputs = process_html(raw, name, work)
            else:
                formatted = beautify_js(raw) if suffix == ".js" else html.unescape(raw)
                output = work / f"{input_path.stem}_cleaned{suffix}"
                output.write_text(formatted, encoding="utf-8")
                report = work / "decode_report.txt"
                report.write_text(
                    "SAFE STATIC CLEAN REPORT\\n"
                    "No code was executed. Formatting does not decrypt protected code.\\n"
                    + "\\n".join(inspect_obfuscation(raw)),
                    encoding="utf-8",
                )
                outputs = [output, report]

            for output in outputs:
                with output.open("rb") as f:
                    await update.message.reply_document(
                        document=f,
                        filename=output.name,
                        caption="Cleaned / analyzed (static only)"
                    )

            await update.message.reply_text(
                "কাজ শেষ। মনে রেখো: custom encryption বা password protection থাকলে "
                "এই cleaner সেটি decrypt করে না; protected অংশ আগের মতোই থাকতে পারে।"
            )
        except Exception as exc:
            await update.message.reply_text(f"ফাইল প্রসেস করা যায়নি: {type(exc).__name__}")


def main():
    token = os.environ.get("BOT_TOKEN")
    if not token:
        raise RuntimeError("BOT_TOKEN environment variable is missing")

    app = Application.builder().token(token).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.run_polling()


if __name__ == "__main__":
    main()
