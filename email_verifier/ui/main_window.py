import sys
import os
import traceback
from typing import List, Optional
import logging
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QFileDialog, QTableWidget,
    QTableWidgetItem, QCheckBox, QProgressBar, QMessageBox,
    QTabWidget, QComboBox, QGroupBox, QSplitter, QMenu, QStatusBar,
    QInputDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize
from PyQt6.QtGui import QAction, QIcon

from email_verifier.models.verification import VerificationResult
from email_verifier.core.verifier import EmailVerifier
from email_verifier.core.database import EmailVerificationDB
from email_verifier.utils.file_utils import read_emails_from_file, save_results_to_csv
from email_verifier.ui.result_table import ResultsTableWidget

logger = logging.getLogger(__name__)


class VerificationWorker(QThread):
    """Worker thread for email verification."""
    progress_updated = pyqtSignal(int, int)  # current, total
    result_ready = pyqtSignal(VerificationResult)
    verification_finished = pyqtSignal()

    def __init__(self, verifier: EmailVerifier, emails: List[str], force_check: bool = False):
        super().__init__()
        self.verifier = verifier
        self.emails = emails
        self.force_check = force_check
        self.should_stop = False

    def run(self):
        total = len(self.emails)
        for i, email in enumerate(self.emails):
            if self.should_stop:
                break

            try:
                result = self.verifier.verify(
                    email, force_check=self.force_check)
                self.result_ready.emit(result)
            except Exception as e:
                logger.error(f"Error verifying {email}: {str(e)}")
                logger.error(traceback.format_exc())

            self.progress_updated.emit(i + 1, total)

        self.verification_finished.emit()

    def stop(self):
        self.should_stop = True


class SearchWorker(QThread):
    """Worker thread for database searches."""
    results_ready = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, db, search_term=None, deliverable_filter=None, domain_filter=None, get_all=False):
        super().__init__()
        self.db = db
        self.search_term = search_term
        self.deliverable_filter = deliverable_filter
        self.domain_filter = domain_filter
        self.get_all = get_all
        self.stopped = False

    def stop(self):
        """Signal the thread to stop."""
        self.stopped = True

    def run(self):
        if self.stopped:
            return

        try:
            if self.get_all:
                # Just get all results (limited to 1000)
                results = self.db.get_all_results(limit=1000)
            else:
                # Using search function with filters
                results = self.db.search_results(
                    self.search_term, self.deliverable_filter, self.domain_filter
                )

            if not self.stopped:
                self.results_ready.emit(results)
        except Exception as e:
            logger.error(f"Search worker error: {str(e)}")
            logger.error(traceback.format_exc())
            if not self.stopped:
                self.error_occurred.emit(str(e))


class DomainsWorker(QThread):
    """Worker thread for loading domain summary."""
    domains_ready = pyqtSignal(list)
    error_occurred = pyqtSignal(str)

    def __init__(self, db):
        super().__init__()
        self.db = db

    def run(self):
        try:
            domains = self.db.get_domains_summary()
            self.domains_ready.emit(domains)
        except Exception as e:
            logger.error(f"Domains worker error: {str(e)}")
            logger.error(traceback.format_exc())
            self.error_occurred.emit(str(e))


class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self, db_path: str = "email_verification.db"):
        super().__init__()
        self.db_path = db_path
        self.verifier = EmailVerifier(db_path=db_path)
        self.db = self.verifier.db

        self.worker = None
        self.search_worker = None
        self.domains_worker = None
        self.current_results = []

        # Connect aboutToQuit signal to cleanup threads
        QApplication.instance().aboutToQuit.connect(self.cleanup_threads)

        self.init_ui()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Email Verifier")
        self.setMinimumSize(900, 600)

        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Create tabs
        self.create_verification_tab()
        self.create_history_tab()

        # Create status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        # Create menu bar
        self.create_menu_bar()

    def cleanup_threads(self):
        """Clean up threads before application quits."""
        # Clean up verification worker
        if self.worker and self.worker.isRunning():
            self.worker.stop()  # Call the stop method if defined
            self.worker.wait(1000)  # Wait for thread to finish, with timeout
            if self.worker.isRunning():
                self.worker.terminate()

        # Clean up search worker
        if self.search_worker and self.search_worker.isRunning():
            # Wait for thread to finish, with timeout
            self.search_worker.wait(1000)
            if self.search_worker.isRunning():
                self.search_worker.terminate()

        # Clean up domains worker
        if self.domains_worker and self.domains_worker.isRunning():
            # Wait for thread to finish, with timeout
            self.domains_worker.wait(1000)
            if self.domains_worker.isRunning():
                self.domains_worker.terminate()

    def create_menu_bar(self):
        """Create the application menu bar."""
        menu_bar = self.menuBar()

        # File menu
        file_menu = menu_bar.addMenu("&File")

        open_action = QAction("&Open Emails File...", self)
        open_action.triggered.connect(self.select_email_file)
        file_menu.addAction(open_action)

        export_action = QAction("&Export Results...", self)
        export_action.triggered.connect(self.export_results)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Tools menu
        tools_menu = menu_bar.addMenu("&Tools")

        verify_single_action = QAction("Verify &Single Email...", self)
        verify_single_action.triggered.connect(self.verify_single_email)
        tools_menu.addAction(verify_single_action)

        tools_menu.addSeparator()

        settings_action = QAction("&Settings...", self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)

        # Help menu
        help_menu = menu_bar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_verification_tab(self):
        """Create the verification tab with input and results."""
        verification_tab = QWidget()
        layout = QVBoxLayout(verification_tab)

        # Input section
        input_group = QGroupBox("Email Input")
        input_layout = QVBoxLayout(input_group)

        file_layout = QHBoxLayout()
        self.file_path_edit = QLineEdit()
        self.file_path_edit.setReadOnly(True)
        self.file_path_edit.setPlaceholderText(
            "Select a file containing email addresses...")
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.select_email_file)
        file_layout.addWidget(self.file_path_edit)
        file_layout.addWidget(browse_button)
        input_layout.addLayout(file_layout)

        options_layout = QHBoxLayout()
        self.smtp_check_box = QCheckBox("Perform SMTP check")
        self.smtp_check_box.setChecked(True)
        self.force_check_box = QCheckBox("Force re-check of cached results")
        options_layout.addWidget(self.smtp_check_box)
        options_layout.addWidget(self.force_check_box)
        options_layout.addStretch()

        self.verify_button = QPushButton("Verify Emails")
        self.verify_button.clicked.connect(self.start_verification)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop_verification)
        self.stop_button.setEnabled(False)
        options_layout.addWidget(self.verify_button)
        options_layout.addWidget(self.stop_button)

        input_layout.addLayout(options_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        input_layout.addWidget(self.progress_bar)

        layout.addWidget(input_group)

        # Results table
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout(results_group)

        self.results_table = ResultsTableWidget()
        results_layout.addWidget(self.results_table)

        # Export button
        export_layout = QHBoxLayout()
        self.export_button = QPushButton("Export Results...")
        self.export_button.clicked.connect(self.export_results)
        export_layout.addStretch()
        export_layout.addWidget(self.export_button)
        results_layout.addLayout(export_layout)

        layout.addWidget(results_group)

        self.tab_widget.addTab(verification_tab, "Verification")

    def create_history_tab(self):
        """Create the history tab with search and filters."""
        history_tab = QWidget()
        layout = QVBoxLayout(history_tab)

        # Search section
        search_group = QGroupBox("Search & Filter")
        search_layout = QHBoxLayout(search_group)

        search_layout.addWidget(QLabel("Search:"))
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search by email or domain...")
        self.search_edit.returnPressed.connect(self.search_history)
        search_layout.addWidget(self.search_edit)

        search_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "Deliverable", "Undeliverable"])
        self.status_filter.currentIndexChanged.connect(self.search_history)
        search_layout.addWidget(self.status_filter)

        search_layout.addWidget(QLabel("Domain:"))
        self.domain_filter = QComboBox()
        self.domain_filter.addItem("All")
        self.domain_filter.currentIndexChanged.connect(self.search_history)
        search_layout.addWidget(self.domain_filter)

        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.search_history)
        search_layout.addWidget(self.search_button)

        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_search)
        search_layout.addWidget(clear_button)

        layout.addWidget(search_group)

        # History table
        self.history_table = ResultsTableWidget()
        layout.addWidget(self.history_table)

        # Actions section
        actions_layout = QHBoxLayout()
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.load_history)

        self.delete_selected_button = QPushButton("Delete Selected")
        self.delete_selected_button.clicked.connect(self.delete_selected)

        self.export_history_button = QPushButton("Export History...")
        self.export_history_button.clicked.connect(self.export_history)

        actions_layout.addWidget(self.refresh_button)
        actions_layout.addWidget(self.delete_selected_button)
        actions_layout.addStretch()
        actions_layout.addWidget(self.export_history_button)

        layout.addLayout(actions_layout)

        self.tab_widget.addTab(history_tab, "History")

        # Load initial history
        QTimer.singleShot(100, self.load_history)

    def select_email_file(self):
        """Open a file dialog to select an email file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Email File", "", "Text Files (*.txt);;CSV Files (*.csv);;All Files (*)"
        )

        if file_path:
            self.file_path_edit.setText(file_path)
            self.load_emails_from_file(file_path)

    def load_emails_from_file(self, file_path: str):
        """Load emails from the selected file."""
        try:
            emails = read_emails_from_file(file_path)
            if emails:
                QMessageBox.information(
                    self, "Emails Loaded", f"Successfully loaded {len(emails)} emails from file."
                )
                self.emails = emails
            else:
                QMessageBox.warning(
                    self, "No Emails Found", "No valid email addresses were found in the file."
                )
        except Exception as e:
            logger.error(f"Error loading email file: {str(e)}")
            logger.error(traceback.format_exc())
            QMessageBox.critical(
                self, "Error Loading File", f"An error occurred while loading the file: {str(e)}"
            )

    def start_verification(self):
        """Start the email verification process."""
        if not hasattr(self, 'emails') or not self.emails:
            QMessageBox.warning(
                self, "No Emails", "Please select a file containing email addresses first."
            )
            return

        # Update verifier settings
        self.verifier.perform_smtp_check = self.smtp_check_box.isChecked()

        # Clear previous results
        self.results_table.clear_results()
        self.current_results = []

        # Setup and start worker thread
        self.worker = VerificationWorker(
            self.verifier, self.emails, force_check=self.force_check_box.isChecked()
        )
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.result_ready.connect(self.handle_result)
        self.worker.verification_finished.connect(self.verification_finished)

        # Update UI
        self.verify_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage("Verification in progress...")

        # Start verification
        self.worker.start()

    def stop_verification(self):
        """Stop the ongoing verification process."""
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.status_bar.showMessage("Verification stopped by user.")

    def update_progress(self, current: int, total: int):
        """Update the progress bar."""
        percentage = int((current / total) * 100) if total > 0 else 0
        self.progress_bar.setValue(percentage)
        self.status_bar.showMessage(
            f"Verifying: {current} of {total} ({percentage}%)")

    def handle_result(self, result: VerificationResult):
        """Handle a verification result."""
        try:
            # Store the result
            self.current_results.append(result)

            # Queue UI update to happen in the main thread
            QTimer.singleShot(0, lambda: self.results_table.add_result(result))
        except Exception as e:
            logger.error(f"Error handling verification result: {str(e)}")
            logger.error(traceback.format_exc())

    def verification_finished(self):
        """Handle the end of the verification process."""
        self.verify_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage(
            f"Verification completed. {len(self.current_results)} emails processed.")

        # Refresh history tab if it's active
        if self.tab_widget.currentIndex() == 1:
            self.load_history()

    def export_results(self):
        """Export the current results to a CSV file."""
        if not self.current_results:
            QMessageBox.warning(
                self, "No Results", "There are no results to export."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Results", "", "CSV Files (*.csv);;All Files (*)"
        )

        if file_path:
            try:
                if save_results_to_csv(self.current_results, file_path, VerificationResult.get_csv_header()):
                    QMessageBox.information(
                        self, "Export Successful", f"Results successfully exported to {file_path}"
                    )
                else:
                    QMessageBox.critical(
                        self, "Export Failed", "An error occurred while exporting the results."
                    )
            except Exception as e:
                logger.error(f"Error exporting results: {str(e)}")
                logger.error(traceback.format_exc())
                QMessageBox.critical(
                    self, "Export Error", f"An error occurred: {str(e)}"
                )

    def load_history(self):
        """Load verification history from the database."""
        try:
            # Show loading indicator
            self.status_bar.showMessage("Loading history...")
            self.refresh_button.setEnabled(False)

            # Create and start worker thread to load all results
            self.search_worker = SearchWorker(self.db, get_all=True)
            self.search_worker.results_ready.connect(self.on_history_loaded)
            self.search_worker.error_occurred.connect(self.on_search_error)
            self.search_worker.finished.connect(
                lambda: self.refresh_button.setEnabled(True))
            self.search_worker.start()
        except Exception as e:
            logger.error(f"Error loading history: {str(e)}")
            logger.error(traceback.format_exc())
            self.status_bar.showMessage(f"Error loading history: {str(e)}")
            self.refresh_button.setEnabled(True)

    def on_history_loaded(self, results):
        """Handle loaded history results."""
        try:
            # Update the table with results
            self.history_table.set_results(results)

            # Update domain filter (in a separate thread)
            self.load_domains()

            # Update status bar
            self.status_bar.showMessage(
                f"Loaded {len(results)} history records")
        except Exception as e:
            logger.error(f"Error displaying history: {str(e)}")
            logger.error(traceback.format_exc())
            self.status_bar.showMessage(f"Error loading history: {str(e)}")

    def load_domains(self):
        """Load domain summary in a separate thread."""
        self.domains_worker = DomainsWorker(self.db)
        self.domains_worker.domains_ready.connect(self.on_domains_loaded)
        self.domains_worker.error_occurred.connect(
            lambda msg: logger.error(f"Error loading domains: {msg}"))
        self.domains_worker.start()

    def on_domains_loaded(self, domains):
        """Handle loaded domains data."""
        try:
            # Store current selection
            current_text = self.domain_filter.currentText()

            # Clear and repopulate
            self.domain_filter.clear()
            self.domain_filter.addItem("All")

            for domain_info in domains:
                domain = domain_info['domain']
                if domain:
                    self.domain_filter.addItem(domain)

            # Restore selection if possible
            index = self.domain_filter.findText(current_text)
            if index >= 0:
                self.domain_filter.setCurrentIndex(index)
        except Exception as e:
            logger.error(f"Error updating domain filter: {str(e)}")
            logger.error(traceback.format_exc())

    def closeEvent(self, event):
        """Handle window close event."""
        # Clean up threads before closing
        self.cleanup_threads()
        event.accept()

    def search_history(self):
        """Search history with current filters."""
        # Show loading indicator
        self.status_bar.showMessage("Searching...")

        # Disable search button
        self.search_button.setEnabled(False)

        # Get search parameters
        search_term = self.search_edit.text().strip()

        # Get deliverable filter
        status_index = self.status_filter.currentIndex()
        deliverable_filter = None
        if status_index == 1:  # Deliverable
            deliverable_filter = True
        elif status_index == 2:  # Undeliverable
            deliverable_filter = False

        # Get domain filter
        domain_filter = None
        if self.domain_filter.currentIndex() > 0:
            domain_filter = self.domain_filter.currentText()

        # Clean up any existing worker
        if self.search_worker and self.search_worker.isRunning():
            self.search_worker.wait()  # Wait for thread to finish

        # Create and start the worker thread
        self.search_worker = SearchWorker(
            self.db, search_term, deliverable_filter, domain_filter
        )

        # Connect signals
        self.search_worker.results_ready.connect(self.on_search_results_ready)
        self.search_worker.error_occurred.connect(self.on_search_error)
        self.search_worker.finished.connect(
            lambda: self.search_button.setEnabled(True))

        # Start the worker
        self.search_worker.start()

    def on_search_results_ready(self, results):
        """Handle search results."""
        try:
            # Update the table with results
            self.history_table.set_results(results)

            # Update status bar
            self.status_bar.showMessage(
                f"Found {len(results)} results matching your search criteria.")
        except Exception as e:
            logger.error(f"Error displaying search results: {str(e)}")
            logger.error(traceback.format_exc())
            self.status_bar.showMessage(f"Error displaying results: {str(e)}")

    def on_search_error(self, error_message):
        """Handle search errors."""
        logger.error(f"Search error: {error_message}")

        # Show error message
        QMessageBox.critical(
            self, "Search Error", f"An error occurred during search: {error_message}"
        )

        # Update status bar
        self.status_bar.showMessage("Search failed")

        # Re-enable the search button
        self.search_button.setEnabled(True)

    def clear_search(self):
        """Clear search filters and reload history."""
        self.search_edit.clear()
        self.status_filter.setCurrentIndex(0)
        self.domain_filter.setCurrentIndex(0)
        self.load_history()

    def delete_selected(self):
        """Delete selected results from the database."""
        selected_rows = self.history_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(
                self, "No Selection", "Please select one or more rows to delete."
            )
            return

        emails_to_delete = []
        for row in sorted(selected_rows, key=lambda x: x.row(), reverse=True):
            index = row.row()
            result = self.history_table.get_result_at_row(index)
            if result:
                emails_to_delete.append(result.email)

        if emails_to_delete:
            confirm = QMessageBox.question(
                self, "Confirm Deletion",
                f"Are you sure you want to delete {len(emails_to_delete)} verification results?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if confirm == QMessageBox.StandardButton.Yes:
                try:
                    if self.db.delete_results(emails_to_delete):
                        self.load_history()
                        QMessageBox.information(
                            self, "Deletion Successful",
                            f"Successfully deleted {len(emails_to_delete)} verification results."
                        )
                    else:
                        QMessageBox.critical(
                            self, "Deletion Failed",
                            "An error occurred while deleting the verification results."
                        )
                except Exception as e:
                    logger.error(f"Error deleting results: {str(e)}")
                    logger.error(traceback.format_exc())
                    QMessageBox.critical(
                        self, "Deletion Error", f"An error occurred: {str(e)}"
                    )

    def export_history(self):
        """Export the filtered history results to a CSV file."""
        results = self.history_table.get_all_results()
        if not results:
            QMessageBox.warning(
                self, "No Results", "There are no results to export."
            )
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export History", "", "CSV Files (*.csv);;All Files (*)"
        )

        if file_path:
            try:
                if save_results_to_csv(results, file_path, VerificationResult.get_csv_header()):
                    QMessageBox.information(
                        self, "Export Successful", f"History successfully exported to {file_path}"
                    )
                else:
                    QMessageBox.critical(
                        self, "Export Failed", "An error occurred while exporting the history."
                    )
            except Exception as e:
                logger.error(f"Error exporting history: {str(e)}")
                logger.error(traceback.format_exc())
                QMessageBox.critical(
                    self, "Export Error", f"An error occurred: {str(e)}"
                )

    def verify_single_email(self):
        """Show a dialog to verify a single email address."""
        email, ok = QInputDialog.getText(
            self, "Verify Single Email", "Enter an email address to verify:"
        )

        if ok and email:
            try:
                # Show busy cursor and disable UI
                QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)

                # Perform verification
                result = self.verifier.verify(email, force_check=True)

                # Restore cursor
                QApplication.restoreOverrideCursor()

                message = (
                    f"Email: {result.email}\n"
                    f"Deliverable: {'Yes' if result.is_deliverable else 'No'}\n"
                    f"Valid Format: {'Yes' if result.is_valid_format else 'No'}\n"
                    f"Domain: {result.domain or 'N/A'}\n"
                    f"Has MX Records: {'Yes' if result.has_mx_records else 'No'}\n"
                )

                if result.smtp_check is not None:
                    message += f"SMTP Check: {'Passed' if result.smtp_check else 'Failed'}\n"
                    if result.smtp_response:
                        message += f"SMTP Response: {result.smtp_response}\n"

                QMessageBox.information(
                    self, "Email Verification Result", message
                )

                # Refresh history if needed
                if self.tab_widget.currentIndex() == 1:
                    self.load_history()

            except Exception as e:
                # Restore cursor
                QApplication.restoreOverrideCursor()

                logger.error(f"Error verifying single email: {str(e)}")
                logger.error(traceback.format_exc())
                QMessageBox.critical(
                    self, "Verification Error", f"An error occurred: {str(e)}"
                )

    def show_settings(self):
        """Show settings dialog."""
        # Placeholder for now
        QMessageBox.information(
            self, "Settings", "Settings dialog not implemented yet."
        )

    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self, "About Email Verifier",
            "Email Verifier 1.0\n\n"
            "A tool to verify if email addresses exist and can receive emails.\n\n"
            "Features:\n"
            "- Email format validation\n"
            "- MX record checking\n"
            "- SMTP verification\n"
            "- Batch processing from files\n"
            "- Result history and filtering\n\n"
            "Created with Python and PyQt6"
        )
