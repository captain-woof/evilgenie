"""
Interactive terminal menus for evilgenie.

Arrow keys to move, SPACE to select/deselect (multi), ENTER to confirm.
Thin wrapper over simple-term-menu with graceful fallback to plain input()
when the library is unavailable or the terminal is not interactive.
"""

try:
    from simple_term_menu import TerminalMenu
    _HAVE_STM = True
except ImportError:
    _HAVE_STM = False


def _menu(entries, title, multi, preselected=(), cursor=0):
    kwargs = dict(
        menu_entries=entries,
        title=title,
        multi_select=multi,
        show_multi_select_hint=multi,
        clear_screen=False,
    )
    if multi:
        # ENTER accepts the checked set as-is (empty allowed); SPACE toggles.
        kwargs["multi_select_select_on_accept"] = False
        kwargs["multi_select_empty_ok"] = True
        if preselected:
            kwargs["preselected_entries"] = list(preselected)
    else:
        kwargs["cursor_index"] = cursor
    try:
        menu = TerminalMenu(**kwargs)
    except TypeError:
        kwargs.pop("preselected_entries", None)  # older simple-term-menu
        kwargs.pop("cursor_index", None)
        menu = TerminalMenu(**kwargs)
    return menu


def multi_select(title, entries, preselected=()):
    """
    Checkbox menu. Returns sorted list of chosen indices.
    preselected: iterable of indices initially checked.
    """
    if not entries:
        return []
    if _HAVE_STM:
        menu = _menu(entries, title, multi=True, preselected=preselected)
        menu.show()
        return sorted(menu.chosen_menu_indices or [])
    # fallback: comma-separated indices
    print(f"\n{title}")
    for i, e in enumerate(entries):
        mark = "*" if i in preselected else " "
        print(f"  [{i}] {mark} {e}")
    raw = input("Comma-separated numbers (empty = preselected): ").strip()
    if not raw:
        return sorted(preselected)
    return sorted(int(x) for x in raw.split(",") if x.strip().isdigit())


def single_select(title, entries, preselect=0):
    """Single-choice menu. Returns chosen index or None if cancelled."""
    if not entries:
        return None
    if _HAVE_STM:
        menu = _menu(entries, title, multi=False, cursor=preselect)
        return menu.show()
    print(f"\n{title}")
    for i, e in enumerate(entries):
        print(f"  [{i}] {e}")
    raw = input(f"Number (default {preselect}): ").strip()
    if not raw:
        return preselect
    return int(raw) if raw.isdigit() else preselect


def text_input(prompt, default=""):
    """Plain text prompt with a default."""
    raw = input(f"{prompt} [{default}]: ").strip()
    return raw if raw else default


def confirm(prompt, default=True):
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} [{hint}]: ").strip().lower()
    if not raw:
        return default
    return raw.startswith("y")
