import os
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

load_dotenv()

_scheduler = None

def start(scan_job_fn):
    global _scheduler
    interval_hours = int(os.getenv("SCAN_INTERVAL_HOURS", "6"))
    _scheduler = BackgroundScheduler()
    _scheduler.add_job(scan_job_fn, "interval", hours=interval_hours, id="vuln_scan")
    _scheduler.start()
    print(f"[scheduler] Scan job scheduled every {interval_hours} hour(s).")

def stop():
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)

def next_run_time():
    if _scheduler:
        job = _scheduler.get_job("vuln_scan")
        if job and job.next_run_time:
            return job.next_run_time.strftime("%Y-%m-%d %H:%M:%S")
    return "not scheduled"