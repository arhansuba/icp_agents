class DuplicateIntegrationError(Exception):
    """Exception raised when there is a duplicate in integration names."""

    def __init__(self, message: str = "Duplicate integration name found.", integration_name: str = ""):
        self.integration_name = integration_name
        super().__init__(f"{message} Integration: {integration_name}")

    def __str__(self) -> str:
        return f"{self.args[0]}"
