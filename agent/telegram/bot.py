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


class TelegramBot:
    def __init__(self, agent: PrecogAgent | None = None):
        self.settings = get_settings()
        if not self.settings.telegram_bot_token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN not set")
        self.token = self.settings.telegram_bot_token
        self.allow = self.settings.allowed_chat_ids
        self.agent = agent or PrecogAgent()
        self.offset = 0

    def _url(self, method: str) -> str:
        return f"{API}/bot{self.token}/{method}"

    def send(self, chat_id: int, text: str, reply_markup: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"chat_id": chat_id, "text": text[:4000]}
        if reply_markup:
            payload["reply_markup"] = reply_markup
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

    def _offer_plan(self, chat_id: int, plan) -> None:
        markup = {
            "inline_keyboard": [[
                {"text": "Approve", "callback_data": f"approve:{plan.id}"},
                {"text": "Reject", "callback_data": f"reject:{plan.id}"},
            ]]
        }
        self.send(chat_id, plan.summary_text() + "\n\nApprove to run.", reply_markup=markup)

    def handle_message(self, chat_id: int, text: str) -> None:
        if not self._allowed(chat_id):
            self.send(chat_id, "Unauthorized chat. Set TELEGRAM_ALLOWED_CHAT_IDS.")
            self.agent.audit.log("telegram_denied", chat_id=chat_id)
            return
        text = (text or "").strip()
        if text.startswith("/start") or text.startswith("/help"):
            wf = "\n".join(f"• {k}: {v}" for k, v in WORKFLOWS.items())
            self.send(
                chat_id,
                "Precog online.\n"
                "/doctor /tools /workflows /kali\n"
                "/workflow domain_recon example.com\n"
                "/workflow vuln_map example.com\n"
                "/workflow kyc_empresa 00000000000191\n"
                "/workflow br_osint\n\n"
                f"Workflows:\n{wf}",
            )
            return
        if text.startswith("/doctor"):
            self.send(chat_id, json.dumps(self.agent.doctor(), indent=2, default=str)[:3500])
            return
        if text.startswith("/tools"):
            self.send(chat_id, ", ".join(t["name"] for t in self.agent.list_tools()))
            return
        if text.startswith("/workflows"):
            self.send(chat_id, "\n".join(f"{k}: {v}" for k, v in self.agent.list_workflows().items()))
            return
        if text.startswith("/kali"):
            d = self.agent.doctor()
            self.send(
                chat_id,
                f"kali_enabled={d.get('kali_enabled')} reachable={d.get('kali_reachable')} "
                f"container={d.get('kali_container')}",
            )
            return
        if text.startswith("/workflow"):
            parts = text.split(maxsplit=2)
            if len(parts) < 2:
                self.send(chat_id, "Usage: /workflow NAME [target|cnpj]")
                return
            name = parts[1].strip()
            rest = parts[2].strip() if len(parts) > 2 else ""
            try:
                plan = self.agent.plan(
                    rest or name,
                    workflow=name,
                    target=None if name == "kyc_empresa" else (rest or None),
                    cnpj=rest if name == "kyc_empresa" else None,
                    include_active=name == "vuln_map",
                )
            except Exception as e:  # noqa: BLE001
                self.send(chat_id, f"Workflow error: {e}")
                return
            self._offer_plan(chat_id, plan)
            return

        include_active = "--active" in text or "nmap" in text.lower() or "vuln" in text.lower()
        plan = self.agent.plan(text, include_active=include_active)
        self._offer_plan(chat_id, plan)

    def handle_callback(self, chat_id: int, data: str, callback_id: str) -> None:
        if not self._allowed(chat_id):
            return
        with httpx.Client(timeout=15.0) as client:
            client.post(self._url("answerCallbackQuery"), json={"callback_query_id": callback_id})
        action, _, plan_id = data.partition(":")
        if action == "reject":
            self.agent.reject(plan_id)
            self.send(chat_id, f"Plan {plan_id} rejected.")
            return
        if action == "approve":
            self.agent.approve(plan_id)
            if plan_id not in self.agent.plans:
                self.send(chat_id, "Plan expired; send objective again.")
                return
            result = self.agent.run(plan_id)
            if not result.approved:
                self.send(chat_id, f"Blocked: {result.results}")
                return
            self.send(chat_id, f"Done {plan_id}. Report: {result.report_path}")
            if result.report_path:
                try:
                    self.send_document(chat_id, result.report_path)
                except Exception as e:  # noqa: BLE001
                    self.send(chat_id, f"(attach failed: {e})")

    def poll_forever(self) -> None:
        console.print("[green]Telegram long-polling started[/green]")
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
