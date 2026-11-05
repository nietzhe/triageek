from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone

DAILY = "daily"
WEEKLY = "weekly"
MONTHLY = "monthly"
KINDS = (DAILY, WEEKLY, MONTHLY)

KIND_LABELS = {DAILY: "Daily", WEEKLY: "Weekly", MONTHLY: "Monthly"}
KIND_WHEN = {DAILY: "on this day", 
             WEEKLY: "during this week", 
             MONTHLY: "during this month"}


@dataclass(frozen=True)
class Period:
    kind: str
    start: datetime
    end: datetime

    @property
    def first_day(self) -> date:
        return self.start.date()

    @property
    def last_day(self) -> date:
        return (self.end - timedelta(days=1)).date()

    @property
    def title(self) -> str:
        return f"{KIND_LABELS[self.kind]} security report"

    @property
    def when(self) -> str:
        return KIND_WHEN[self.kind]

    @property
    def label(self) -> str:
        if self.kind == DAILY:
            return format_day(self.first_day)
        
        if self.kind == WEEKLY:
            return f"{format_day(self.first_day)} to {format_day(self.last_day)}"
        
        return f"{self.first_day:%B} {self.first_day.year}"


def format_day(day: date) -> str:
    return f"{day.day} {day:%b} {day.year}"


def _midnight(day: date) -> datetime:
    return datetime.combine(day, time.min, tzinfo=timezone.utc)


def build_period(kind: str, day: date) -> Period:
    if kind == DAILY:
        first, after = day, day + timedelta(days=1)
    elif kind == WEEKLY:
        first = day - timedelta(days=day.weekday())  # monday
        after = first + timedelta(days=7)
    elif kind == MONTHLY:
        first = day.replace(day=1)
        after = (first + timedelta(days=32)).replace(day=1)
    else:
        raise ValueError(f"Unknown report kind: {kind!r}")
    
    return Period(kind=kind, start=_midnight(first), end=_midnight(after))
