import telebot
import os
import tempfile
import lief  # библиотека для анализа ELF/PE

# ---------------- Токен безопасно через переменные окружения ----------------
TOKEN = os.environ.get("TOKEN")  # добавь токен через Secrets в Replit
bot = telebot.TeleBot(TOKEN)

# ---------------- Функция сканирования файла ----------------
def scan_file(file_path):
    offsets = []
    binary = lief.parse(file_path)
    if not binary:
        return offsets

    # Функции
    for func in getattr(binary, 'functions', []):
        offsets.append({
            "Name": func.name,
            "Type": "Function",
            "Address": hex(func.address)
        })

    # Глобальные переменные
    for symbol in getattr(binary, 'symbols', []):
        if symbol.type in [lief.ELF.SYMBOL_TYPES.OBJECT, getattr(lief.PE, 'SYMBOL_TYPE', None)]:
            offsets.append({
                "Name": symbol.name,
                "Type": "Variable",
                "Address": hex(symbol.value)
            })
    return offsets

# ---------------- Обработка полученного файла ----------------
@bot.message_handler(content_types=['document'])
def handle_file(message):
    file_info = bot.get_file(message.document.file_id)
    downloaded_file = bot.download_file(file_info.file_path)

    # Сохраняем временно во сне
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(downloaded_file)
        tmp_path = tmp_file.name

    offsets = scan_file(tmp_path)
    os.remove(tmp_path)

    if not offsets:
        bot.send_message(message.chat.id, "Файл не удалось распарсить или нет символов.")
        return

    response = "Во сне извлеченные оффсеты:\n"
    for o in offsets[:50]:  # ограничение для удобства
        response += f"{o['Type']} | {o['Name']} | {o['Address']}\n"

    bot.send_message(message.chat.id, response)

# ---------------- Запуск бота ----------------
bot.polling()