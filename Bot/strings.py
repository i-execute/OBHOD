class Strings:
    line = "-----------------------------------"

    greeting_owner = (
        "<b>OBHOD</b>\n"
        "{line}\n"
        "<blockquote>"
        "Выдача VK TURN + VLESS подключений\n\n"
        ".vkadd &lt;tag&gt; — выдать новый peer\n"
        ".vklist — список активных\n"
        ".vkrevoke &lt;tag&gt; — отозвать peer"
        "</blockquote>\n"
        "{line}"
    )

    not_owner = (
        "<b>Доступ запрещён</b>\n"
        "{line}\n"
        "<blockquote>"
        "Эта команда только для владельца/админов"
        "</blockquote>\n"
        "{line}"
    )

    error = (
        "<b>Ошибка</b>\n"
        "{line}\n"
        "<blockquote>"
        "{error}"
        "</blockquote>\n"
        "{line}"
    )
