import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

import numpy as np
import onnx
import onnxruntime as ort
import requests
from diskcache import Cache

logger = logging.getLogger(__name__)

class ICPModel:
    """
    A class to manage the lifecycle and predictions of models using local ONNX runtime sessions.

    Attributes:
        session (ort.InferenceSession | None): An ONNX runtime inference session for executing model predictions locally.
        model_path (str): The file path to the local ONNX model used for predictions.
        output_path (str): The file path where the model output will be saved after processing.

    Args:
        model_path (Optional[str]): The path to the ONNX model file. Must be provided to initialize the model.
        output_path (Optional[str]): The directory where the model output will be stored. If not specified, a default temporary path will be used.

    Raises:
        ValueError: If neither model_path nor output_path is provided, or if the model_path does not point to a valid ONNX file.
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        output_path: Optional[str] = None,
    ):
        if model_path is None:
            raise ValueError("model_path must be provided.")

        if model_path and ".onnx" in model_path:
            logger.debug(f"Starting ONNX session from {model_path}")
            self.session = ort.InferenceSession(model_path)

        self._cache = Cache(os.path.join(os.getcwd(), "tmp", "cachedir"))
        if output_path is not None:
            self._output_path = output_path
        else:
            self._output_path = os.path.join(
                tempfile.gettempdir(),
                f"{Path(model_path).stem}"
            )
        logger.debug(f"Output Path: {self._output_path}")
        self.session = self._set_session(model_path)

    def _set_session(self, model_path: str) -> Optional[ort.InferenceSession]:
        """
        Set onnxruntime session for the model.

        Returns:
            An ONNX InferenceSession.
        """
        try:
            if model_path in self._cache:
                file_path = Path(self._cache.get(model_path))
                with open(file_path, "rb") as f:
                    onnx_model = f.read()

            return ort.InferenceSession(onnx_model)

        except Exception as e:
            logger.error(f"Could not load model: {e}")
            return None

    def predict(
        self,
        input_feed: Optional[Dict] = None
    ) -> Optional[np.ndarray]:
        """
        Makes a prediction using a local ONNX session.

        Args:
            input_feed (Optional[Dict]): A dictionary containing the input data for prediction. Defaults to None.

        Returns:
            A numpy array containing the predictions.

        Raises:
            ValueError: If required parameters are not provided or the session is not initialized.
        """
        try:
            logger.info("Predicting")
            if self.session is None:
                raise ValueError("Session is not initialized.")
            if input_feed is None:
                raise ValueError("Input feed is none")
            preds = self.session.run(None, input_feed)[0]
            return preds
        except Exception as e:
            logger.error(f"An error occurred in predict: {e}")
            raise e

    def _download_model(self, model_url: str) -> None:
        """
        Downloads the model from the specified URL.

        Args:
            model_url (str): The URL from which to download the model.

        """
        try:
            logger.info("Downloading model... 🚀")
            response = requests.get(model_url)
            response.raise_for_status()
            
            save_path = Path(self._output_path)
            with open(save_path, "wb") as f:
                f.write(response.content)

            self._cache[self._output_path] = save_path
            logger.info(f"Model saved at: {save_path} ✅")
        except Exception as e:
            logger.error(f"Failed to download model: {e}")
