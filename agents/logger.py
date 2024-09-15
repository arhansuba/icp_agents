import logging
from typing import List, Tuple


class WordReplacerFilter(logging.Filter):
    def __init__(self, replacements: List[Tuple[str, str]]):
        """
        Initializes the filter with a list of word replacements.

        Args:
            replacements (List[Tuple[str, str]]): A list of tuples where each tuple contains a word to be replaced and its replacement.
        """
        super().__init__()
        self.replacements = replacements

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Applies the word replacements to the log message.

        Args:
            record (logging.LogRecord): The log record.

        Returns:
            bool: Always returns True to ensure the log record is processed.
        """
        for old, new in self.replacements:
            record.msg = record.msg.replace(old, new)
        return True

# Example usage
replacements = [
    ("flow", "action"),
    ("Flow", "Action"),
    ("deployment", "action deployment"),
    ("Deployment", "Action Deployment")
]

word_replacer_filter = WordReplacerFilter(replacements)
logger = logging.getLogger(__name__)
logger.addFilter(word_replacer_filter)