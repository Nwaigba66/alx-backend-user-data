#!/usr/bin/env python3
"""This module define a filterred logger function
"""
import logging
import re
from typing import List

pat = "{}=(?P<{}>.*?){}"
fd = re.findall
PII_FIELDS = ["name", "email", "phone", "password", "ip"]


def filter_datum(
        fields: List[str],
        redaction: str,
        message: str,
        separator: str) -> str:
    """Perform filtering and replacement"""
    n = fd("".join([pat.format(fi, fi, separator) for fi in fields]), message)
    va = "" if not n else "|".join(["=" + i for i in n[0]])
    return message if not fields else re.sub(va, "=" + redaction, message)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """format for the log message"""
        record.msg = filter_datum(
                self.fields, self.REDACTION, record.msg, self.SEPARATOR)
        return super().format(record)


def get_logger() -> logging.Logger:
    """Get a new logger
    """
    this_logger = logging.Logger(
            name="user_data",
            level=logging.INFO,
            propagate=False)
    stream = logging.StreamHandler()
    stream.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    this_logger.setHandler(logging.StreamHandler(stream))
    return this_logger
