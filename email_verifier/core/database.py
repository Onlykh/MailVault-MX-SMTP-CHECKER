import sqlite3
import os
from typing import List, Optional, Dict, Any
import logging

from email_verifier.models.verification import VerificationResult

logger = logging.getLogger(__name__)


class EmailVerificationDB:
    """Database for storing email verification results."""

    def __init__(self, db_path: str = "email_verification.db"):
        """Initialize database."""
        self.db_path = db_path
        self._create_tables_if_not_exist()

    def _create_tables_if_not_exist(self):
        """Create tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS verification_results (
                email TEXT PRIMARY KEY,
                is_valid_format INTEGER,
                domain TEXT,
                has_mx_records INTEGER,
                mx_records TEXT,
                smtp_check INTEGER,
                smtp_response TEXT,
                verified_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            conn.commit()

    def get_result(self, email: str) -> Optional[VerificationResult]:
        """Get verification result for an email."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM verification_results WHERE email = ?",
                    (email,)
                )
                row = cursor.fetchone()

                if row:
                    return VerificationResult.from_dict(dict(row))
        except Exception as e:
            logger.error(f"Error retrieving result for {email}: {str(e)}")
        return None

    def save_result(self, result: VerificationResult) -> bool:
        """Save verification result to database."""
        try:
            data = result.to_dict()
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Convert booleans to integers for SQLite
                for key in ['is_valid_format', 'has_mx_records']:
                    data[key] = 1 if data[key] else 0

                # Handle None values for smtp_check
                if data['smtp_check'] is not None:
                    data['smtp_check'] = 1 if data['smtp_check'] else 0

                columns = ', '.join(data.keys())
                placeholders = ', '.join(['?'] * len(data))
                values = tuple(data.values())

                query = f"INSERT OR REPLACE INTO verification_results ({columns}) VALUES ({placeholders})"
                cursor.execute(query, values)
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error saving result for {result.email}: {str(e)}")
            return False

    def get_all_results(self, limit: int = None, offset: int = 0) -> List[VerificationResult]:
        """Get all verification results with pagination."""
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = "SELECT * FROM verification_results ORDER BY created_at DESC"
                params = []

                if limit is not None:
                    query += " LIMIT ? OFFSET ?"
                    params.extend([limit, offset])

                cursor.execute(query, params)
                rows = cursor.fetchall()

                results = [VerificationResult.from_dict(
                    dict(row)) for row in rows]
        except Exception as e:
            logger.error(f"Error retrieving all results: {str(e)}")
        return results

    def search_results(self, search_term: str,
                       deliverable_filter: Optional[bool] = None,
                       domain_filter: Optional[str] = None) -> List[VerificationResult]:
        """Search verification results with filters."""
        results = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()

                query = "SELECT * FROM verification_results WHERE 1=1"
                params = []

                if search_term:
                    query += " AND (email LIKE ? OR domain LIKE ?)"
                    params.extend([f"%{search_term}%", f"%{search_term}%"])

                if deliverable_filter is not None:
                    if deliverable_filter:
                        query += " AND is_valid_format = 1 AND has_mx_records = 1 AND (smtp_check IS NULL OR smtp_check = 1)"
                    else:
                        query += " AND (is_valid_format = 0 OR has_mx_records = 0 OR smtp_check = 0)"

                if domain_filter:
                    query += " AND domain = ?"
                    params.append(domain_filter)

                query += " ORDER BY created_at DESC"

                cursor.execute(query, params)
                rows = cursor.fetchall()

                results = [VerificationResult.from_dict(
                    dict(row)) for row in rows]
        except Exception as e:
            logger.error(f"Error searching results: {str(e)}")
        return results

    def count_results(self) -> int:
        """Count total verification results."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM verification_results")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Error counting results: {str(e)}")
            return 0

    def get_domains_summary(self) -> List[Dict[str, Any]]:
        """Get summary of domains and their verification status."""
        domains = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT domain, 
                           COUNT(*) as total,
                           SUM(CASE WHEN is_valid_format = 1 AND has_mx_records = 1 
                                   AND (smtp_check IS NULL OR smtp_check = 1) 
                                   THEN 1 ELSE 0 END) as deliverable
                    FROM verification_results
                    GROUP BY domain
                    ORDER BY total DESC
                """)
                rows = cursor.fetchall()
                domains = [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Error getting domains summary: {str(e)}")
        return domains

    def delete_results(self, emails: List[str]) -> bool:
        """Delete verification results for the specified emails."""
        if not emails:
            return False

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                placeholders = ','.join(['?'] * len(emails))
                cursor.execute(
                    f"DELETE FROM verification_results WHERE email IN ({placeholders})", emails)
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"Error deleting results: {str(e)}")
            return False
