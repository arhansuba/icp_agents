from functools import wraps
from typing import Any, Callable

from prefect import task as prefect_task


def task(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    A decorator to wrap a function as a Prefect task with error handling.

    Args:
        func (Callable[..., Any]): The function to be wrapped as a task.

    Returns:
        Callable[..., Any]: The wrapped function as a Prefect task.
    """
    @wraps(func)
    def safe_func(*args: Any, **kwargs: Any) -> Any:
        """
        Executes the wrapped function and handles exceptions.

        Args:
            *args: Positional arguments for the wrapped function.
            **kwargs: Keyword arguments for the wrapped function.

        Returns:
            Any: The result of the wrapped function.

        Raises:
            Exception: Reraises any exception encountered during function execution.
        """
        try:
            return func(*args, **kwargs)
        except Exception as e:
            # Log the exception or handle it as needed
            raise e

    return prefect_task(safe_func)
