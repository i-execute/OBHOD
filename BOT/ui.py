from __future__ import annotations

import re
from dataclasses import dataclass
from html import escape
from typing import Iterable

from goygram.rich import Rich

from . import i18n, icons

MAX_BUTTONS = 18
COPY_TEXT_LIMIT = 256
MAX_CALLBACK = 64
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
SEP = " · "
_ICONS = False


def use_icons(value: bool) -> None:
    global _ICONS
    _ICONS = bool(value)


def icons_on() -> bool:
    return _ICONS


def ico(name: object, tail: str = " ") -> str:
    if not _ICONS:
        return ""
    mark = icons.markup(name)
    return mark + tail if mark else ""


def esc(value: object) -> str:
    return escape(CONTROL.sub("", str(value)), quote=True)


def code(value: object) -> str:
    return f"<code>{esc(value)}</code>"


def bold(value: object) -> str:
    return f"<b>{esc(value)}</b>"


def italic(value: object) -> str:
    return f"<i>{esc(value)}</i>"


def muted(value: object) -> str:
    return f'<span style="color: #8a8a8a">{esc(value)}</span>'


def chip(value: object) -> str:
    return f"<mark>{esc(value)}</mark>"


@dataclass
class Button:
    label: str
    data: str
    style: str = ""
    icon: str = ""

    def html(self) -> str:
        if len(self.data.encode("utf-8")) > MAX_CALLBACK:
            raise ValueError(f"callback data is too long: {self.data}")
        style = f' style="{esc(self.style)}"' if self.style else ""
        body = ico(self.icon, "") + esc(self.label)
        return f'<tg-button type="callback_data"{style} data="{esc(self.data)}">{body}</tg-button>'


def button(label: str, data: str, style: str = "", icon: str = "") -> Button:
    return Button(label=label, data=data, style=style, icon=icon)


def copy_button(label: str, text: str, icon: str = "copy") -> str:
    return f'<tg-button type="copy_text" text="{esc(text)}">{ico(icon, "")}{esc(label)}</tg-button>'


def copy_row(label: str, text: str, icon: str = "copy") -> str:
    token = str(text or "")
    if not token or len(token) > COPY_TEXT_LIMIT:
        return ""
    return row(copy_button(label, token, icon))


def long_payload(text: str, limit: int = 3500) -> str:
    token = str(text or "")
    if not token:
        return ""
    return pre(token[:limit])


def long_block(title: str, text: str, limit: int = 3500) -> str:
    body = long_payload(text, limit)
    if not body:
        return ""
    return details(title, body)


def fitted(label: str, text: str, lang: str = i18n.DEFAULT_LANGUAGE) -> tuple[str, str]:
    button = copy_row(label, text)
    if button:
        return button, ""
    block = long_block(i18n.t("UI_LONG_TITLE", lang), text)
    if not block:
        return "", ""
    return "", block + f"<p>{muted(i18n.t('UI_LONG_HINT', lang))}</p>"


def link_button(label: str, url: str, icon: str = "link") -> str:
    return f'<tg-button type="url" url="{esc(url)}">{ico(icon, "")}{esc(label)}</tg-button>'


def input_row(label: str, ident: str, ctx: object = "-", lang: str = "en") -> str:
    from . import i18n, inline

    buttons = [inline_button(label, inline.prefill(ident, ctx), icon="tag")]
    if inline.has_options(ident):
        buttons.append(inline_button(i18n.t("BTN_LIST", lang), inline.list_query(ident, ctx), icon="compass"))
    return row(*buttons)


def inline_button(label: str, query: str, style: str = "", icon: str = "") -> str:
    attr = f' style="{esc(style)}"' if style else ""
    return f'<tg-button type="switch_inline_query_current_chat"{attr} query="{esc(query)}">{ico(icon, "")}{esc(label)}</tg-button>'


def inline_row(label: str, query: str, style: str = "", extra: Iterable[str] = ()) -> str:
    items = [inline_button(label, query, style)] + [item for item in extra if item]
    return '<tg-button-row align="left">' + "".join(items) + "</tg-button-row>"


def row(*buttons: Button | str, align: str = "left") -> str:
    flat: list[Button | str] = []
    for item in buttons:
        if isinstance(item, (list, tuple)):
            flat.extend(item)
        else:
            flat.append(item)
    inner = "".join(item.html() if isinstance(item, Button) else item for item in flat)
    return f'<tg-button-row align="{esc(align)}">{inner}</tg-button-row>'


def big(label: str, data: str, style: str = "", icon: str = "") -> str:
    return row(button(label, data, style, icon), align="left")


def rows(items: Iterable[str]) -> str:
    return "".join(items)


def row_parts(item: object) -> tuple[str, str, object]:
    if isinstance(item, (list, tuple)):
        values = list(item)
        if len(values) == 2:
            return "", str(values[0]), values[1]
        if len(values) >= 3:
            return str(values[0] or ""), str(values[1]), values[2]
    return "", str(item), ""


def table(pairs: Iterable[object], headers: tuple[str, str] | None = None) -> str:
    head = ""
    if headers:
        head = f"<tr><th>{esc(headers[0])}</th><th>{esc(headers[1])}</th></tr>"
    cells = []
    for item in pairs:
        icon, key, value = row_parts(item)
        label = ico(icon, "") + esc(key)
        cells.append(f"<tr><td>{label}</td><td>{value}</td></tr>")
    body = "".join(cells)
    return f'<table bordered="false" striped="false">{head}{body}</table>'


def loading(title: str, body: str, steps: Iterable[str] = (), icon: str = "loading") -> str:
    items = "".join("<li>%s</li>" % esc(item) for item in steps)
    listing = "<ul>%s</ul>" % items if items else ""
    blocks = [f"<p>{muted(body)}</p>"] if body else []
    if listing:
        blocks.append(listing)
    return screen(title, "", blocks, [], icon=icon)


def bullet_list(items: Iterable[str]) -> str:
    return "<ul>" + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def numbered(items: Iterable[str]) -> str:
    return "<ol>" + "".join(f"<li>{item}</li>" for item in items) + "</ol>"


def details(title: str, body: str, open_: bool = False) -> str:
    flag = " open" if open_ else ""
    return f"<details{flag}><summary>{esc(title)}</summary>{body}</details>"


def quote(body: str, cite: str = "") -> str:
    if cite:
        return f"<blockquote>{body}<cite>{esc(cite)}</cite></blockquote>"
    return f"<blockquote>{body}</blockquote>"


def heading(text: str, level: int = 3, icon: str = "") -> str:
    return f"<h{level}>{ico(icon, '')}{esc(text)}</h{level}>"


def divider() -> str:
    return "<hr/>"


def pre(text: str, lang: str = "") -> str:
    if lang:
        return f'<pre><code class="language-{esc(lang)}">{esc(text)}</code></pre>'
    return f"<pre>{esc(text)}</pre>"


def screen(
    title: str,
    subtitle: str = "",
    blocks: Iterable[str] = (),
    buttons: Iterable[str] = (),
    footer: str = "",
    icon: str = "",
) -> Rich:
    root = Rich()
    root.add(f"<h2>{ico(icon, '')}{esc(title)}</h2>")
    if subtitle:
        root.add(f"<p>{subtitle}</p>")
    for block in blocks:
        if block:
            root.add(block)
    button_html = [item for item in buttons if item]
    if button_html:
        root.add(divider())
        for item in button_html:
            root.add(item)
    if footer:
        root.add(f"<footer>{footer}</footer>")
    return root


def status_line(connected: bool, running: bool, installed: bool, lang: str = i18n.DEFAULT_LANGUAGE) -> str:
    if not connected:
        return chip(ico("fail", "") + i18n.t("STATUS_NOT_CONNECTED", lang))
    if not installed:
        return chip(ico("warn", "") + i18n.t("STATUS_NOT_INSTALLED", lang))
    if running:
        return chip(ico("ok", "") + i18n.t("STATUS_RUNNING", lang))
    return chip(ico("stop", "") + i18n.t("STATUS_STOPPED", lang))


def count_buttons(html: str) -> int:
    return html.count("<tg-button ")


def validate_buttons(html: str) -> None:
    total = count_buttons(html)
    if total > MAX_BUTTONS:
        raise ValueError(f"too many buttons: {total}")
