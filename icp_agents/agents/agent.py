import json
import logging
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Self, Tuple, Union

from ape import Contract, accounts, networks
from ape.api import AccountAPI
from ape.contracts import ContractInstance
from ape.exceptions import NetworkError
from ape_accounts.accounts import InvalidPasswordError
from requests import HTTPError

logger = logging.getLogger(__name__)


class ICPAgent:
    """
    Agents are intermediaries between users and Smart Contracts, facilitating seamless interaction with verifiable models and executing associated contracts. Uses Ape framework to verify a model proof off-chain, sign it with the user's account, and send results to a select EVM chain to execute code.
    """

    def __init__(
        self,
        id: int,
        version_id: int,
        contracts: Optional[Dict[str, Union[str, List[str]]]] = None,
        integrations: Optional[List[str]] = None,
        chain: Optional[str] = None,
        account: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Args:
            id (int): The ID of the model.
            version_id (int): The version of the model.
            contracts (Dict[str, str]): The contracts to handle, must be a dictionary with the contract name as the key and the contract address as the value.
            integrations (List[str]): The integrations to use.
            chain (str): The name of the blockchain network.
            account (str): The account to use.
            **kwargs: Additional keyword arguments.
        """
        self.id = id
        self.version_id = version_id
        self.contracts = contracts or {}
        self.integrations = integrations or []
        self.chain = chain
        self.account = account

        self._check_passphrase_in_env()
        self._check_or_create_account()
        self.contract_handler = ContractHandler(self.contracts, self.integrations)

        # Useful for testing
        network_parser: Callable = kwargs.get(
            "network_parser", networks.parse_network_choice
        )

        try:
            self._provider = network_parser(self.chain)
        except NetworkError:
            logger.error(f"Chain {self.chain} not found")
            raise ValueError(f"Chain {self.chain} not found")

    def _check_or_create_account(self) -> None:
        """
        Check if the account exists in the execution environment, if not create it.
        """
        try:
            accounts.load(self.account)
        except Exception:
            logger.info(f"Account {self.account} not found locally, creating it")
            account_path = Path.home().joinpath(".ape/accounts")
            logger.info(f"Creating account {self.account} at {account_path}")
            account_path.mkdir(parents=True, exist_ok=True)
            with open(account_path / f"{self.account}.json", "w") as f:
                json.dump({"account_data": "dummy_data"}, f)  # Replace with actual account data
            logger.info(f"Account {self.account} created")

    def _check_passphrase_in_env(self) -> None:
        """
        Check if the passphrase is in the environment variables.
        """
        if self.account is None:
            raise ValueError("Account is not specified.")

        if f"{self.account.upper()}_PASSPHRASE" not in os.environ:
            logger.error(
                f"Passphrase for account {self.account} not found in environment variables. Passphrase must be stored in an environment variable named {self.account.upper()}_PASSPHRASE."
            )
            raise ValueError(
                f"Passphrase for account {self.account} not found in environment variables"
            )

    @contextmanager
    def execute(self) -> Any:
        """
        Execute the agent in the given ecosystem. Return the contract instance so the user can execute it.
        """
        logger.debug("Provider configured")
        with self._provider:
            self._account = accounts.load(self.account)
            logger.debug("Account loaded")
            try:
                if self.account is None:
                    raise ValueError("Account is not specified.")
                self._account.set_autosign(
                    True, passphrase=os.getenv(f"{self.account.upper()}_PASSPHRASE")
                )
            except InvalidPasswordError as e:
                logger.error(
                    f"Invalid passphrase for account {self.account}. Could not decrypt account."
                )
                raise ValueError(
                    f"Invalid passphrase for account {self.account}. Could not decrypt account."
                ) from e
            logger.debug("Autosign enabled")
            with accounts.use_sender(self._account) as sender:
                yield self.contract_handler.handle(account=sender)

    def predict(
        self,
        input_file: Optional[str] = None,
        input_feed: Optional[Dict] = None,
        verifiable: bool = False,
        fp_impl: str = "FP16x16",
        custom_output_dtype: Optional[str] = None,
        job_size: str = "M",
        dry_run: bool = False,
        model_category: Optional[str] = None,
        **result_kwargs: Any,
    ) -> Optional[Union[Tuple[Any, Any], "AgentResult"]]:
        """
        Runs a round of inference on the model and saves the result.

        Args:
            input_file: The input file to use for inference
            input_feed: The input feed to use for inference
            job_size: The size of the job to run
        """
        # Placeholder for actual prediction logic
        result = ({"prediction": "dummy_result"}, "request_id_dummy")

        if not verifiable:
            logger.warning(
                "Inference is not verifiable. No request ID was returned. No proof will be generated."
            )
            return result

        if result is None:
            raise ValueError("The prediction result is None!")
        if isinstance(result, tuple):
            pred, request_id = result
            return AgentResult(
                input=input_feed,
                request_id=request_id,
                result=pred,
                agent=self,
                dry_run=dry_run,
                **result_kwargs,
            )
        else:
            raise ValueError("We are expecting result to be a tuple!")


class AgentResult:
    """
    A class to represent the result of an agent's inference.
    """

    def __init__(
        self,
        input: Any,
        request_id: str,
        result: Any,
        agent: ICPAgent,
        **kwargs: Any,
    ):
        """
        Args:
            input (list): The input to the agent.
            request_id (str): The request ID of the proof.
            value (int): The value of the inference.
        """
        self.input: Any = input
        self.request_id: str = request_id
        self.__value: Any = result
        self.verified: bool = False
        self._timeout: int = kwargs.get("timeout", 600)
        self._poll_interval: int = kwargs.get("poll_interval", 10)
        self._dry_run: bool = kwargs.get("dry_run", False)

        if not self._dry_run:
            self._proof_job: Job = self._get_proof_job()
        logger.debug(f"{self} created")

    def __repr__(self) -> str:
        return f"AgentResult(input={self.input}, request_id={self.request_id}, value={self.__value})"

    def _get_proof_job(self) -> Job:
        """
        Get the proof job.
        """
        # Placeholder for actual proof job retrieval logic
        return Job(request_id=self.request_id, status=JobStatus.COMPLETED)

    @property
    def value(self) -> Any:
        """
        Get the value of the inference.
        """
        if self.verified:
            return self.__value
        self._verify()
        return self.__value

    def _verify(self) -> None:
        """
        Verify the proof. Check for the proof job, if its done start the verify job, then wait for verification.
        """
        if self._dry_run:
            logger.warning("Dry run enabled. Skipping verification.")
            self.verified = True
            return

        self._wait_for_proof()
        self.verified = self._verify_proof()

    def _wait_for_proof(self) -> None:
        """
        Wait for the proof job to finish.
        """
        self._wait_for(self._proof_job, self._timeout, self._poll_interval)

    def _verify_proof(self) -> bool:
        """
        Verify the proof.
        """
        # Placeholder for actual proof verification logic
        return True

    def _wait_for(
        self,
        job: Job,
        timeout: int = 600,
        poll_interval: int = 10,
    ) -> None:
        """
        Wait for a job to finish.

        Args:
            job (Job): The job to wait for.
            timeout (int): The timeout.
            poll_interval (int): The poll interval.

        Raises:
            ValueError: If the job failed.
            TimeoutError: If the job timed out.
        """
        start_time = time.time()
        wait_timeout = start_time + float(timeout)

        while True:
            now = time.time()
            if job.status == JobStatus.COMPLETED:
                logger.info("Job completed")
                return
            elif job.status == JobStatus.FAILED:
                logger.error("Job failed")
                raise ValueError("Job failed")
            elif now > wait_timeout:
                logger.error("Job timed out")
                raise TimeoutError("Job timed out")
            else:
                logger.info(f"Job is still running, elapsed time: {now - start_time}")
            time.sleep(poll_interval)


class ContractHandler:
    """
    A class to handle multiple contracts and its executions.

    The initiation of the contracts must be done inside ape's provider context,
    which means that it should be done inside the ICPAgent's execute context.
    """

    def __init__(
        self,
        contracts: Optional[Dict[str, Union[str, List[str]]]] = None,
        integrations: Optional[List[str]] = None,
    ) -> None:
        if contracts is None and integrations is None:
            raise ValueError("Contracts or integrations must be specified.")
        if contracts is None:
            contracts = {}
        if integrations is None:
            integrations = []
        contract_names = list(contracts.keys())
        duplicates = set(contract_names) & set(integrations)
        if duplicates:
            duplicate_names = ", ".join(duplicates)
            raise DuplicateIntegrationError(
                f"Integrations of these names already exist: {duplicate_names}. Choose different contract names."
            )
        self._contracts = contracts
        logger.debug(f"Contracts: {self._contracts}")
        self._integrations = integrations
        logger.debug(f"Integrations: {self._integrations}")
        self._contracts_instances: Dict[str, ContractInstance] = {}
        self._integrations_instances: Dict[str, IntegrationFactory] = {}

    def __getattr__(self, name: str) -> Union[ContractInstance, IntegrationFactory]:
        """
        Get the contract by name.
        """
        if name in self._contracts_instances.keys():
            return self._contracts_instances[name]
        if name in self._integrations_instances.keys():
            return self._integrations_instances[name]

    def _initiate_contract(
        self, address: str, abi: Optional[str] = None
    ) -> ContractInstance:
        """
        Initiate the contract.
        """
        logger.debug(f"Initiating contract with address {address}")
        if not abi:
            return Contract(address=address)
        return Contract(address=address, abi=abi)

    def _initiate_integration(
        self, name: str, account: AccountAPI
    ) -> IntegrationFactory:
        """
        Initiate the integration.
        """
        logger.debug(f"Initiating integration with name {name}")
        return IntegrationFactory.from_name(name, sender=account)

    def handle(self, account: Optional[AccountAPI] = None) -> Self:
        """
        Handle the contracts.
        """
        try:
            if self._contracts:
                for name, contract_data in self._contracts.items():
                    if isinstance(contract_data, str):
                        address = contract_data
                        self._contracts_instances[name] = self._initiate_contract(
                            address
                        )
                    elif isinstance(contract_data, list):
                        if len(contract_data) == 1:
                            address = contract_data[0]
                            self._contracts_instances[name] = self._initiate_contract(
                                address
                            )
                        else:
                            address, abi = contract_data
                            self._contracts_instances[name] = self._initiate_contract(
                                address, abi
                            )
            for name in self._integrations:
                self._integrations_instances[name] = self._initiate_integration(
                    name, account
                )
        except NetworkError as e:
            logger.error(f"Failed to initiate contract: {e}")
            raise ValueError(
                f"Failed to initiate contract: {e}. Make sure this is executed inside `ICPAgent.execute()` or a provider context."
            )

        return self