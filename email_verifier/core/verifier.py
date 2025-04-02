import dns.resolver
import re
import socket
import smtplib
import logging
from typing import List, Tuple, Optional
from email.utils import parseaddr

from email_verifier.models.verification import VerificationResult
from email_verifier.core.database import EmailVerificationDB

logger = logging.getLogger(__name__)


class EmailVerifier:
    """Verifies if an email address exists and is deliverable."""

    def __init__(self, perform_smtp_check=True, db_path: str = "email_verification.db"):
        # RFC 5322 compliant email regex
        self.email_pattern = re.compile(
            r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
        self.resolver = dns.resolver.Resolver()
        # Use Google's public DNS for reliability
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        self.perform_smtp_check = perform_smtp_check
        # Use a real-looking email for SMTP tests
        self.from_email = "verifier@example.com"
        # Socket timeout for SMTP connections (in seconds)
        self.timeout = 10
        # Initialize database
        self.db = EmailVerificationDB(db_path)

    def is_valid_email_format(self, email: str) -> bool:
        """Check if the email has a valid format according to RFC 5322."""
        # First use parseaddr to handle edge cases
        _, addr = parseaddr(email)
        if not addr:
            return False
        return bool(self.email_pattern.match(addr))

    def get_domain(self, email: str) -> Optional[str]:
        """Extract domain from email address."""
        try:
            return email.split('@')[1]
        except IndexError:
            return None

    def check_mx_records(self, domain: str) -> Tuple[bool, List[str]]:
        """Check if the domain has MX records."""
        try:
            mx_records = self.resolver.resolve(domain, 'MX')
            return True, [str(mx.exchange).rstrip('.') for mx in mx_records]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            return False, []
        except Exception as e:
            logger.error(f"Error checking MX records for {domain}: {str(e)}")
            return False, []

    def verify_smtp(self, email: str, mx_records: List[str]) -> Tuple[bool, Optional[str]]:
        """Verify email existence using SMTP."""
        if not mx_records:
            return False, "No MX records available"

        # Try each MX server until we get a definitive answer
        for mx_server in mx_records:
            try:
                # Set timeout for socket operations
                socket.setdefaulttimeout(self.timeout)

                smtp = smtplib.SMTP(mx_server)
                smtp.ehlo_or_helo_if_needed()

                # Some servers require HELO before MAIL FROM
                smtp.ehlo_or_helo_if_needed()

                # Send MAIL FROM command
                smtp_code, smtp_response = smtp.mail(self.from_email)
                if smtp_code != 250:
                    smtp.quit()
                    continue

                # Send RCPT TO command - this checks if the mailbox exists
                smtp_code, smtp_response = smtp.rcpt(email)
                smtp.quit()

                if smtp_code == 250:
                    # 250 means the mailbox exists
                    return True, f"Mailbox exists (Code: {smtp_code})"
                elif smtp_code == 550:
                    # 550 usually means the mailbox doesn't exist
                    return False, f"Mailbox doesn't exist (Code: {smtp_code})"
                else:
                    # Other codes are inconclusive
                    return None, f"Inconclusive result (Code: {smtp_code}, Response: {smtp_response})"

            except smtplib.SMTPServerDisconnected as e:
                logger.warning(f"Server {mx_server} disconnected: {str(e)}")
                continue
            except smtplib.SMTPResponseException as e:
                # SMTP error with a specific error code
                return False, f"SMTP Error: {e.smtp_code} - {e.smtp_error}"
            except (socket.timeout, socket.error, smtplib.SMTPException) as e:
                logger.warning(f"Error connecting to {mx_server}: {str(e)}")
                continue
            except Exception as e:
                logger.error(
                    f"Unexpected error during SMTP verification: {str(e)}")
                return None, f"Verification error: {str(e)}"

        # If we tried all servers but couldn't get a definitive answer
        return None, "Could not verify with any MX server"

    def verify(self, email: str, force_check: bool = False) -> VerificationResult:
        """
        Verify if an email address exists and is deliverable.

        Args:
            email: Email address to verify
            force_check: Force verification even if the result is in the database

        Returns:
            VerificationResult object with the verification results
        """
        # Check if we already have this email in the database
        if not force_check:
            existing_result = self.db.get_result(email)
            if existing_result:
                logger.info(f"Found existing verification for {email}")
                return existing_result

        # Validate email format
        is_valid_format = self.is_valid_email_format(email)

        # If format is invalid, return early
        if not is_valid_format:
            result = VerificationResult(email=email, is_valid_format=False)
            self.db.save_result(result)
            return result

        # Extract domain
        domain = self.get_domain(email)

        # Check MX records
        has_mx, mx_records = self.check_mx_records(domain)

        # Initialize result without SMTP check
        result = VerificationResult(
            email=email,
            is_valid_format=is_valid_format,
            domain=domain,
            has_mx_records=has_mx,
            mx_records=mx_records
        )

        # Perform SMTP verification if enabled and MX records exist
        if self.perform_smtp_check and has_mx and mx_records:
            try:
                smtp_check, smtp_response = self.verify_smtp(email, mx_records)
                result.smtp_check = smtp_check
                result.smtp_response = smtp_response
            except Exception as e:
                logger.error(f"Error during SMTP verification: {str(e)}")
                result.smtp_response = f"Verification error: {str(e)}"

        # Save result to database
        self.db.save_result(result)

        return result
