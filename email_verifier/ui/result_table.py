from typing import List, Optional
import logging
from PyQt6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView,
    QAbstractItemView, QMenu, QApplication
)
from PyQt6.QtCore import Qt, QPoint
from PyQt6.QtGui import QColor, QBrush, QAction

from email_verifier.models.verification import VerificationResult

logger = logging.getLogger(__name__)


class ResultsTableWidget(QTableWidget):
    """Custom table widget for displaying verification results."""

    def __init__(self):
        super().__init__()
        self.results = []
        self.init_ui()

    def init_ui(self):
        """Initialize the table UI."""
        # Set column count and headers
        headers = [
            "Email", "Status", "Valid Format", "Domain",
            "MX Records", "SMTP Check", "Verified At"
        ]
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)

        # Set table properties
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(
            QAbstractItemView.SelectionMode.ExtendedSelection)

        # Set column widths
        self.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch)  # Email
        for i in range(1, len(headers)):
            self.horizontalHeader().setSectionResizeMode(
                i, QHeaderView.ResizeMode.ResizeToContents)

        # Enable context menu
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def add_result(self, result: VerificationResult):
        """Add a single result to the table."""
        self.results.append(result)

        row = self.rowCount()
        self.insertRow(row)

        # Email
        self.setItem(row, 0, QTableWidgetItem(result.email))

        # Status
        status_item = QTableWidgetItem(
            "Deliverable" if result.is_deliverable else "Undeliverable")
        status_item.setForeground(
            QBrush(QColor("green" if result.is_deliverable else "red")))
        self.setItem(row, 1, status_item)

        # Valid Format
        self.setItem(row, 2, QTableWidgetItem(
            "Yes" if result.is_valid_format else "No"))

        # Domain
        self.setItem(row, 3, QTableWidgetItem(result.domain or ""))

        # MX Records
        mx_text = "Yes" if result.has_mx_records else "No"
        if result.has_mx_records and result.mx_records:
            mx_text = f"Yes ({len(result.mx_records)})"
        self.setItem(row, 4, QTableWidgetItem(mx_text))

        # SMTP Check
        smtp_text = "Not Checked"
        if result.smtp_check is not None:
            smtp_text = "Passed" if result.smtp_check else "Failed"
            if result.smtp_response:
                smtp_text += f" - {result.smtp_response}"
        self.setItem(row, 5, QTableWidgetItem(smtp_text))

        # Verified At
        self.setItem(row, 6, QTableWidgetItem(result.verified_at))

    def set_results(self, results: List[VerificationResult]):
        """Set all results at once."""
        self.clear_results()

        # Store results but don't modify during iteration
        self.results = results.copy()  # Make a copy to be safe

        # Temporarily disable sorting and updates for better performance
        self.setSortingEnabled(False)
        self.setUpdatesEnabled(False)

        # Pre-allocate rows - more efficient than inserting one by one
        self.setRowCount(len(self.results))

        # Add all results without calling add_result to avoid recursion
        for row, result in enumerate(self.results):
            try:
                # Email
                self.setItem(row, 0, QTableWidgetItem(result.email))

                # Status
                status_item = QTableWidgetItem(
                    "Deliverable" if result.is_deliverable else "Undeliverable")
                status_item.setForeground(
                    QBrush(QColor("green" if result.is_deliverable else "red")))
                self.setItem(row, 1, status_item)

                # Valid Format
                self.setItem(row, 2, QTableWidgetItem(
                    "Yes" if result.is_valid_format else "No"))

                # Domain
                self.setItem(row, 3, QTableWidgetItem(result.domain or ""))

                # MX Records
                mx_text = "Yes" if result.has_mx_records else "No"
                if result.has_mx_records and result.mx_records:
                    mx_text = f"Yes ({len(result.mx_records)})"
                self.setItem(row, 4, QTableWidgetItem(mx_text))

                # SMTP Check
                smtp_text = "Not Checked"
                if result.smtp_check is not None:
                    smtp_text = "Passed" if result.smtp_check else "Failed"
                    if result.smtp_response:
                        smtp_text += f" - {result.smtp_response}"
                self.setItem(row, 5, QTableWidgetItem(smtp_text))

                # Verified At
                self.setItem(row, 6, QTableWidgetItem(result.verified_at))

            except Exception as e:
                logger.error(f"Error adding result row {row}: {str(e)}")
                continue

        # Re-enable updates and sorting
        self.setUpdatesEnabled(True)
        self.setSortingEnabled(True)

    def clear_results(self):
        """Clear all results from the table."""
        self.results = []
        self.setRowCount(0)

    def get_result_at_row(self, row: int) -> Optional[VerificationResult]:
        """Get the result object at the specified row."""
        if 0 <= row < len(self.results):
            return self.results[row]
        return None

    def get_all_results(self) -> List[VerificationResult]:
        """Get all results currently in the table."""
        return self.results

    def get_selected_results(self) -> List[VerificationResult]:
        """Get results for the selected rows."""
        selected_rows = set(index.row() for index in self.selectedIndexes())
        return [self.results[row] for row in selected_rows if 0 <= row < len(self.results)]

    def show_context_menu(self, pos: QPoint):
        """Show context menu for the table."""
        global_pos = self.mapToGlobal(pos)

        menu = QMenu(self)

        # Add copy action
        copy_action = QAction("Copy Selected Emails", self)
        copy_action.triggered.connect(self.copy_selected_emails)
        menu.addAction(copy_action)

        # Add copy all action
        copy_all_action = QAction("Copy All Emails", self)
        copy_all_action.triggered.connect(self.copy_all_emails)
        menu.addAction(copy_all_action)

        # Add deliverable filter actions
        menu.addSeparator()

        # Only show if there are results
        if self.results:
            copy_deliverable_action = QAction("Copy Deliverable Emails", self)
            copy_deliverable_action.triggered.connect(
                lambda: self.copy_filtered_emails(True))
            menu.addAction(copy_deliverable_action)

            copy_undeliverable_action = QAction(
                "Copy Undeliverable Emails", self)
            copy_undeliverable_action.triggered.connect(
                lambda: self.copy_filtered_emails(False))
            menu.addAction(copy_undeliverable_action)

        menu.exec(global_pos)

    def copy_selected_emails(self):
        """Copy selected email addresses to clipboard."""
        selected_results = self.get_selected_results()
        if selected_results:
            emails = [result.email for result in selected_results]
            QApplication.clipboard().setText("\n".join(emails))

    def copy_all_emails(self):
        """Copy all email addresses to clipboard."""
        if self.results:
            emails = [result.email for result in self.results]
            QApplication.clipboard().setText("\n".join(emails))

    def copy_filtered_emails(self, deliverable: bool):
        """Copy filtered email addresses to clipboard."""
        if self.results:
            emails = [
                result.email for result in self.results
                if result.is_deliverable == deliverable
            ]
            QApplication.clipboard().setText("\n".join(emails))
