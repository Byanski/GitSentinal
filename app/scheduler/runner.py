import asyncio
import subprocess
import sys
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from app.database import get_auth, get_setting, get_all_settings
from app.scanner.engine import ScanEngine, scanner_state

logger = logging.getLogger("gitsentinel.scheduler")
scheduler: AsyncIOScheduler = None

def send_desktop_notification(title: str, message: str):
    """Sends a desktop notification using native Windows PowerShell or fallback."""
    if sys.platform == "win32":
        try:
            # Escape strings for PowerShell
            safe_title = title.replace('"', '`"').replace("'", "`'")
            safe_msg = message.replace('"', '`"').replace("'", "`'")
            ps_script = f"""
            [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
            $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
            $textNodes = $template.GetElementsByTagName("text")
            $textNodes.Item(0).AppendChild($template.CreateTextNode("{safe_title}")) > $null
            $textNodes.Item(1).AppendChild($template.CreateTextNode("{safe_msg}")) > $null
            $toast = [Windows.UI.Notifications.ToastNotification.new($template)]
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("GitSentinel").Show($toast)
            """
            subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"Failed to send Windows toast notification: {e}")
    else:
        logger.info(f"[NOTIFICATION] {title}: {message}")

async def scheduled_daily_scan_job():
    """Job executed daily by the scheduler."""
    logger.info("Executing scheduled daily scan job...")
    auth = get_auth()
    if not auth or not auth.get("access_token"):
        logger.warning("Scheduled scan skipped: No GitHub account authenticated.")
        return

    if scanner_state.is_scanning:
        logger.warning("Scheduled scan skipped: Another scan is currently active.")
        return

    engine = ScanEngine(auth["access_token"])
    await engine.run_scan()

    notifications_enabled = get_setting("desktop_notifications", "true").lower() == "true"
    if notifications_enabled:
        findings = scanner_state.total_findings
        if findings > 0:
            send_desktop_notification(
                "GitSentinel Alert: Secrets Detected!",
                f"Daily scan finished. Found {findings} exposed secrets/env vars across your repositories. Review and rotate them now."
            )
        else:
            send_desktop_notification(
                "GitSentinel: Daily Scan Clean",
                f"Daily scan completed. All {scanner_state.scanned_repos} repositories are clean of exposed secrets!"
            )

def configure_scheduler() -> AsyncIOScheduler:
    """Initialize or update the scheduler based on stored settings."""
    global scheduler
    if scheduler is None:
        scheduler = AsyncIOScheduler()
        scheduler.start()

    # Remove existing daily job if present
    if scheduler.get_job("daily_scan_job"):
        scheduler.remove_job("daily_scan_job")

    daily_enabled = get_setting("daily_scan_enabled", "false").lower() == "true"
    if daily_enabled:
        time_str = get_setting("daily_scan_time", "03:00")
        try:
            hour, minute = time_str.split(":")
            scheduler.add_job(
                scheduled_daily_scan_job,
                CronTrigger(hour=int(hour), minute=int(minute)),
                id="daily_scan_job",
                replace_existing=True
            )
            logger.info(f"Daily scan scheduled for {hour.zfill(2)}:{minute.zfill(2)} every day.")
        except Exception as e:
            logger.error(f"Failed to configure daily cron schedule with time '{time_str}': {e}")
    else:
        logger.info("Daily auto-scan is disabled in settings.")

    return scheduler
