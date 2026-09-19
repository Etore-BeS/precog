from __future__ import annotations

import json
import time
from typing import Any

import httpx
from rich.console import Console

from agent.core import PrecogAgent
from agent.settings import get_settings
from agent.workflows.catalog import WORKFLOWS

console = Console()
API = "https://api.telegram.org"

MAIN_KEYBOARD = {
    "keyboard": [
        [{"text": "🔍 Domain recon"}, {"text": "🛡️ Vuln map"}],
        [{"text": "🏢 KYC empresa"}, {"text": "🇧🇷 BR OSINT"}],
        [{"text": "🩺 Doctor"}, {"text": "🐉 Kali status"}],
        [{"text": "🧰 Tools"}, {"text": "📋 Workflows"}],
        [{"text": "❓ Help"}],
    ],
    "resize_keyboard": True,
    "is_persistent": True,
}

LABEL_TO_WORKFLOW = {
    "🔍 Domain recon": "domain_recon",
    "Domain recon": "domain_recon",
    "🛡️ Vuln map": "vuln_map",
    "Vuln map": "vuln_map",
    "🏢 KYC empresa": "kyc_empresa",
    "KYC empresa": "kyc_empresa",
    "🇧🇷 BR OSINT": "br_osint",
    "BR OSINT": "br_osint",
}


class TelegramBot:
    def __init__(self, agent: PrecogAgent | None = None):
        get_settings.cache_clear()
        self.settings = get_settings()
        if not self.settings.telegram_bot_token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN not set")
        self.token = self.settings.telegram_bot_token
        self.allow = self.settings.allowed_chat_ids
        self.agent = agent or PrecogAgent()
        self.offset = 0
        # chat_id -> pending workflow name waiting for target/cnpj
        self.pending: dict[int, str] = {}

    def _url(self, method: str) -> str:
        return f"{API}/bot{self.token}/{method}"

    def send(
        self,
        chat_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
        parse_mode: str | None = None,
    ) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text[:4000]}
        if reply_markup:
            payload["reply_markup"] = reply_markup
        if parse_mode:
            payload["parse_mode"] = parse_mode
        with httpx.Client(timeout=30.0) as client:
            client.post(self._url("sendMessage"), json=payload)

    def send_document(self, chat_id: int, path: str) -> None:
        with httpx.Client(timeout=60.0) as client:
            with open(path, "rb") as f:
                client.post(
                    self._url("sendDocument"),
                    data={"chat_id": str(chat_id)},
                    files={"document": (path.split("/")[-1], f)},
                )

    def get_updates(self) -> list[dict[str, Any]]:
        with httpx.Client(timeout=35.0) as client:
            r = client.get(self._url("getUpdates"), params={"timeout": 25, "offset": self.offset})
            r.raise_for_status()
            return r.json().get("result", [])

    def _allowed(self, chat_id: int) -> bool:
        return bool(self.allow) and chat_id in self.allow

    def _help(self) -> str:
        return (
            "🔥 *Precog* — OSINT / recon (lab)\n\n"
            "Use the buttons below, or type:\n"
            "• domain recon `gallify.dev`\n"
            "• vuln map `gallify.dev`\n"
            "• kyc `00.000.000/0001-91`\n\n"
            "After you pick a workflow, send the *target* (domain) or *CNPJ*.\n"
            "Runs execute immediately (unleashed mode). Audit still logged."
        )

    def _run_workflow(self, chat_id: int, name: str, rest: str) -> None:
        try:
            plan = self.agent.plan(
                rest or name,
                workflow=name,
                target=None if name in {"kyc_empresa", "br_osint"} else (rest or None),
                cnpj=rest if name == "kyc_empresa" else None,
                include_active=name == "vuln_map",
            )
        except Exception as e:  # noqa: BLE001
            self.send(chat_id, f"⚠️ Could not build plan: {e}", reply_markup=MAIN_KEYBOARD)
            return
        self.send(chat_id, "⏳ Running…\n" + plan.summary_text(), reply_markup=MAIN_KEYBOARD)
        # unleashed: auto-approve
        self.agent.approve(plan.id)
        result = self.agent.run(plan.id)
        if not result.approved:
            self.send(chat_id, f"Blocked: {result.results}", reply_markup=MAIN_KEYBOARD)
            return
        self.send(chat_id, f"✅ Done `{plan.id}`\nReport: {result.report_path}", reply_markup=MAIN_KEYBOARD)
        if result.report_path:
            try:
                self.send_document(chat_id, result.report_path)
            except Exception as e:  # noqa: BLE001
                self.send(chat_id, f"(attach failed: {e})")

    def handle_message(self, chat_id: int, text: str) -> None:
        if not self._allowed(chat_id):
            self.send(chat_id, "Unauthorized chat. Set TELEGRAM_ALLOWED_CHAT_IDS.")
            self.agent.audit.log("telegram_denied", chat_id=chat_id)
            return
        text = (text or "").strip()

        if text.startswith("/start") or text in {"❓ Help", "Help", "/help"}:
            self.pending.pop(chat_id, None)
            self.send(chat_id, self._help(), reply_markup=MAIN_KEYBOARD, parse_mode="Markdown")
            return

        if text in {"🩺 Doctor", "Doctor", "/doctor"}:
            self.send(chat_id, json.dumps(self.agent.doctor(), indent=2, default=str)[:3500], reply_markup=MAIN_KEYBOARD)
            return

        if text in {"🐉 Kali status", "Kali status", "/kali"}:
            d = self.agent.doctor()
            self.send(
                chat_id,
                f"🐉 Kali\nenabled={d.get('kali_enabled')}\nreachable={d.get('kali_reachable')}\n"
                f"container={d.get('kali_container')}",
                reply_markup=MAIN_KEYBOARD,
            )
            return

        if text in {"🧰 Tools", "Tools", "/tools"}:
            names = [t["name"] for t in self.agent.list_tools()]
            self.send(chat_id, "🧰 Tools:\n• " + "\n• ".join(names), reply_markup=MAIN_KEYBOARD)
            return

        if text in {"📋 Workflows", "Workflows", "/workflows"}:
            lines = [f"• *{k}*: {v}" for k, v in WORKFLOWS.items()]
            self.send(chat_id, "📋 Workflows:\n" + "\n".join(lines), reply_markup=MAIN_KEYBOARD, parse_mode="Markdown")
            return

        # Button → ask for target
        if text in LABEL_TO_WORKFLOW:
            wf = LABEL_TO_WORKFLOW[text]
            if wf == "br_osint":
                self._run_workflow(chat_id, wf, "")
                return
            self.pending[chat_id] = wf
            hint = "CNPJ (14 digits)" if wf == "kyc_empresa" else "domain or IP (e.g. gallify.dev)"
            self.send(chat_id, f"Selected *{wf}*.\nSend the {hint}:", reply_markup=MAIN_KEYBOARD, parse_mode="Markdown")
            return

        # Pending target/cnpj
        if chat_id in self.pending:
            wf = self.pending.pop(chat_id)
            self._run_workflow(chat_id, wf, text)
            return

        if text.startswith("/workflow"):
            parts = text.split(maxsplit=2)
            if len(parts) < 2:
                self.send(chat_id, "Usage: /workflow NAME [target|cnpj]", reply_markup=MAIN_KEYBOARD)
                return
            name = parts[1].strip()
            rest = parts[2].strip() if len(parts) > 2 else ""
            if not rest and name != "br_osint":
                self.pending[chat_id] = name
                self.send(chat_id, f"Send target/CNPJ for `{name}`:", reply_markup=MAIN_KEYBOARD)
                return
            self._run_workflow(chat_id, name, rest)
            return

        # Free text → plan + run immediately
        include_active = "nmap" in text.lower() or "vuln" in text.lower()
        try:
            plan = self.agent.plan(text, include_active=include_active)
        except Exception as e:  # noqa: BLE001
            self.send(chat_id, f"⚠️ {e}", reply_markup=MAIN_KEYBOARD)
            return
        self.send(chat_id, "⏳ Running…\n" + plan.summary_text(), reply_markup=MAIN_KEYBOARD)
        self.agent.approve(plan.id)
        result = self.agent.run(plan.id)
        if not result.approved:
            self.send(chat_id, f"Blocked: {result.results}", reply_markup=MAIN_KEYBOARD)
            return
        self.send(chat_id, f"✅ Done `{plan.id}`\nReport: {result.report_path}", reply_markup=MAIN_KEYBOARD)
        if result.report_path:
            try:
                self.send_document(chat_id, result.report_path)
            except Exception as e:  # noqa: BLE001
                self.send(chat_id, f"(attach failed: {e})")

    def handle_callback(self, chat_id: int, data: str, callback_id: str) -> None:
        # legacy approve/reject still supported
        if not self._allowed(chat_id):
            return
        with httpx.Client(timeout=15.0) as client:
            client.post(self._url("answerCallbackQuery"), json={"callback_query_id": callback_id})
        action, _, plan_id = data.partition(":")
        if action == "reject":
            self.agent.reject(plan_id)
            self.send(chat_id, f"Plan {plan_id} rejected.", reply_markup=MAIN_KEYBOARD)
            return
        if action == "approve":
            self.agent.approve(plan_id)
            if plan_id not in self.agent.plans:
                self.send(chat_id, "Plan expired; send again.", reply_markup=MAIN_KEYBOARD)
                return
            result = self.agent.run(plan_id)
            self.send(chat_id, f"Done {plan_id}. Report: {result.report_path}", reply_markup=MAIN_KEYBOARD)
            if result.report_path:
                try:
                    self.send_document(chat_id, result.report_path)
                except Exception:
                    pass

    def poll_forever(self) -> None:
        console.print("[green]Telegram long-polling started (menu UX, unleashed)[/green]")
        while True:
            try:
                for u in self.get_updates():
                    self.offset = u["update_id"] + 1
                    if "message" in u:
                        msg = u["message"]
                        self.handle_message(msg["chat"]["id"], msg.get("text", ""))
                    elif "callback_query" in u:
                        cq = u["callback_query"]
                        self.handle_callback(cq["message"]["chat"]["id"], cq.get("data", ""), cq["id"])
            except KeyboardInterrupt:
                break
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]poll error:[/red] {e}")
                time.sleep(2)


def run_bot() -> None:
    TelegramBot().poll_forever()
