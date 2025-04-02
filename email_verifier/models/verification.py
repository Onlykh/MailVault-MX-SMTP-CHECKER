from dataclasses import dataclass, asdict
from datetime import datetime
from typing import List, Optional
import json


@dataclass
class VerificationResult:
    """Data class for email verification results."""
    email: str
    is_valid_format: bool
    domain: Optional[str] = None
    has_mx_records: bool = False
    mx_records: List[str] = None
    smtp_check: Optional[bool] = None
    smtp_response: Optional[str] = None
    verified_at: str = None
    created_at: Optional[str] = None

    def __post_init__(self):
        if self.mx_records is None:
            self.mx_records = []
        if self.verified_at is None:
            self.verified_at = datetime.now().isoformat()

    @property
    def is_deliverable(self) -> bool:
        """Check if the email is likely deliverable based on all checks."""
        if not self.is_valid_format or not self.has_mx_records:
            return False
        if self.smtp_check is not None:
            return self.smtp_check
        return True

    def to_dict(self) -> dict:
        """Convert the result to a dictionary."""
        result = asdict(self)
        # Convert list to JSON string for database storage
        result['mx_records'] = json.dumps(result['mx_records'])
        return result

    @classmethod
    def from_dict(cls, data: dict) -> 'VerificationResult':
        """Create a VerificationResult from a dictionary."""
        # Make a copy to avoid modifying the original
        data_copy = data.copy()

        # Convert JSON string back to list
        if 'mx_records' in data_copy and isinstance(data_copy['mx_records'], str):
            data_copy['mx_records'] = json.loads(data_copy['mx_records'])

        # Remove fields that aren't in the VerificationResult class
        # (This is a fallback in case there are other unexpected fields)
        known_fields = {'email', 'is_valid_format', 'domain', 'has_mx_records',
                        'mx_records', 'smtp_check', 'smtp_response', 'verified_at', 'created_at'}
        for key in list(data_copy.keys()):
            if key not in known_fields:
                data_copy.pop(key)

        return cls(**data_copy)

    def to_csv_row(self) -> List[str]:
        """Convert the result to a CSV row."""
        return [
            self.email,
            str(self.is_deliverable),
            str(self.is_valid_format),
            self.domain or '',
            str(self.has_mx_records),
            ', '.join(self.mx_records) if self.mx_records else '',
            str(self.smtp_check) if self.smtp_check is not None else '',
            self.smtp_response or '',
            self.verified_at or ''
        ]

    @staticmethod
    def get_csv_header() -> List[str]:
        """Get the CSV header row."""
        return [
            'Email',
            'Is Deliverable',
            'Is Valid Format',
            'Domain',
            'Has MX Records',
            'MX Records',
            'SMTP Check',
            'SMTP Response',
            'Verified At'
        ]
