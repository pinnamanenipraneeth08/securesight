"""SecureSight Services"""

from app.services.log_processor import process_logs_batch, normalize_log
from app.services.detection_engine import evaluate_rule, process_logs_for_detection
from app.services.alerting import send_email_alert, send_slack_alert, send_telegram_alert

__all__ = [
    "process_logs_batch",
    "normalize_log",
    "evaluate_rule",
    "process_logs_for_detection",
    "send_email_alert",
    "send_slack_alert",
    "send_telegram_alert",
]
