#!/usr/bin/env python3
"""
Email Verifier - A tool to check if an email address exists and can receive emails
by verifying MX records and performing SMTP verification.
"""

import sys
import os
import logging
from PyQt6.QtWidgets import QApplication

from email_verifier.ui.main_window import MainWindow


def setup_logging():
    """Set up logging configuration."""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    os.makedirs(log_dir, exist_ok=True)

    log_file = os.path.join(log_dir, 'email_verifier.log')

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )


def main():
    """Main application entry point."""
    setup_logging()

    app = QApplication(sys.argv)
    app.setApplicationName("Email Verifier")

    # Set the database path to be in the user's home directory or app directory
    db_path = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), 'email_verification.db')

    # Create and show the main window
    window = MainWindow(db_path=db_path)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
