import os
import csv
from typing import List, Set, Optional
import logging

logger = logging.getLogger(__name__)


def read_emails_from_file(file_path: str) -> List[str]:
    """Read emails from a file, handling different formats."""
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return []

    emails = []

    # Determine file type by extension
    file_ext = os.path.splitext(file_path)[1].lower()

    try:
        if file_ext == '.csv':
            # Try to read as CSV
            with open(file_path, 'r', encoding='utf-8') as f:
                # Try to detect the CSV dialect
                sample = f.read(4096)
                f.seek(0)

                sniffer = csv.Sniffer()
                try:
                    dialect = sniffer.sniff(sample)
                    has_header = sniffer.has_header(sample)
                except:
                    # Fall back to default CSV settings
                    dialect = csv.excel
                    has_header = False

                reader = csv.reader(f, dialect)

                # Skip header if present
                if has_header:
                    next(reader, None)

                for row in reader:
                    if row:  # Make sure row is not empty
                        # Try to find an email in the row
                        for field in row:
                            if '@' in field:
                                emails.append(field.strip())
                                break
        else:
            # Read as plain text file, one email per line
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if '@' in line:
                        # Extract emails if the line has multiple items
                        parts = line.split()
                        for part in parts:
                            if '@' in part:
                                # Remove any punctuation around the email
                                email = part.strip(',.;:"\'<>()')
                                if email:
                                    emails.append(email)
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")

    # Remove duplicates while preserving order
    seen = set()
    unique_emails = []
    for email in emails:
        if email not in seen:
            seen.add(email)
            unique_emails.append(email)

    return unique_emails


def save_results_to_csv(results: List, file_path: str, header: Optional[List[str]] = None) -> bool:
    """Save results to a CSV file."""
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Write header if provided
            if header:
                writer.writerow(header)

            # Write data
            for result in results:
                if hasattr(result, 'to_csv_row'):
                    writer.writerow(result.to_csv_row())
                else:
                    writer.writerow(result)

        return True
    except Exception as e:
        logger.error(f"Error saving to CSV {file_path}: {str(e)}")
        return False
