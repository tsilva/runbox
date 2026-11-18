"""Fixed read-only bucket checks through reviewed loopback S3 signers."""

import re
from urllib.parse import urlsplit

from .config import Error, fields, require

FAILURE_STAGES = frozenset({
    "request-policy", "native-auth", "request-signing", "upstream-connect",
    "upstream-request", "upstream-response", "upstream-status", "response-policy",
    "upstream-tls", "upstream-timeout",
})


def validate(client):
    fields(client, ("type", "targets"))
    require(client["type"] == "s3-head", "Expected the shared S3 bucket check")
    targets = client["targets"]
    require(
        type(targets) is list and 1 <= len(targets) <= 4,
        "A bounded S3 bucket inventory is required",
    )
    selected = set()
    for target in targets:
        fields(
            target,
            ("bucket", "endpoint-variable", "access-variable", "secret-variable"),
        )
        require(
            isinstance(target["bucket"], str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", target["bucket"]),
            "Invalid selected S3 bucket",
        )
        names = [
            target[key]
            for key in ("endpoint-variable", "access-variable", "secret-variable")
        ]
        require(
            all(
                isinstance(name, str) and re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", name)
                for name in names
            )
            and len(set(names)) == 3,
            "S3 checks require distinct public environment selectors",
        )
        identity = (target["bucket"], target["endpoint-variable"])
        require(identity not in selected, "Duplicate S3 bucket check")
        selected.add(identity)


def select(client, environment):
    validate(client)
    result = []
    for target in client["targets"]:
        endpoint = environment.get(target["endpoint-variable"])
        require(isinstance(endpoint, str), "Missing selected S3 transport")
        try:
            parsed = urlsplit(endpoint)
            valid = (
                parsed.scheme == "http"
                and parsed.hostname == "127.0.0.1"
                and parsed.port is not None
                and 1024 <= parsed.port <= 65535
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
                and not parsed.username
                and not parsed.password
            )
        except ValueError:
            valid = False
        require(valid, "S3 checks require a reviewed loopback signing transport")
        credentials = [
            environment.get(target[key])
            for key in ("access-variable", "secret-variable")
        ]
        require(
            all(
                isinstance(value, str)
                and re.fullmatch(r"[a-z][a-z0-9_]{0,100}_placeholder", value)
                for value in credentials
            ),
            "S3 checks accept public placeholders only",
        )
        result.append((target["bucket"], endpoint, *credentials))
    return result


def execute(client, environment, arguments, factory=None, configuration=None):
    require(not arguments, "S3 bucket checks accept no arguments")
    targets = select(client, environment)
    # Import only after validating every target. Explicit SDK credentials prevent
    # provider-chain, local token-store and metadata-service credential discovery.
    if factory is None:
        import boto3
        from botocore.config import Config

        factory, configuration = boto3.client, Config
    status = None
    failure_stage = None
    try:
        for bucket, endpoint, access, secret in targets:
            status = None
            sdk = factory(
                "s3",
                endpoint_url=endpoint,
                region_name="auto",
                aws_access_key_id=access,
                aws_secret_access_key=secret,
                config=configuration(
                    signature_version="s3v4",
                    s3={"addressing_style": "path"},
                    connect_timeout=5,
                    read_timeout=10,
                    retries={"mode": "standard", "total_max_attempts": 1},
                    request_checksum_calculation="when_required",
                    response_checksum_validation="when_required",
                ),
            )
            try:
                response = sdk.head_bucket(Bucket=bucket)
                status = response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                require(
                    type(response) is dict
                    and response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                    == 200,
                    "S3 bucket verification failed",
                )
            finally:
                sdk.close()
    except Exception as error:
        response = getattr(error, "response", None)
        if type(response) is dict and type(response.get("ResponseMetadata")) is dict:
            status = response["ResponseMetadata"].get("HTTPStatusCode")
            headers = response["ResponseMetadata"].get("HTTPHeaders")
            if type(headers) is dict:
                stages = [value for key, value in headers.items()
                          if type(key) is str and key.lower() == "x-runbox-s3-stage"]
                if len(stages) == 1 and type(stages[0]) is str and stages[0] in FAILURE_STAGES:
                    failure_stage = stages[0]
                upstream = [value for key, value in headers.items()
                            if type(key) is str and key.lower() == "x-runbox-s3-upstream-status"]
                if (failure_stage == "upstream-status" and len(upstream) == 1
                        and type(upstream[0]) is str and re.fullmatch(r"[1-5][0-9]{2}", upstream[0])
                        and not 200 <= int(upstream[0]) <= 299):
                    status = int(upstream[0])
        if type(status) is int and (400 <= status <= 599 or (
                failure_stage == "upstream-status" and 100 <= status <= 399 and not 200 <= status <= 299)):
            # The parent already admits exactly this numeric-only diagnostic.
            # Never include SDK error messages, headers or provider bodies.
            detail = f"; S3 stage {failure_stage}" if failure_stage is not None else ""
            raise Error(f"Service request failed (HTTP {status}{detail}); details withheld") from None
        raise Error(
            "S3 bucket verification failed; private diagnostics withheld"
        ) from None
    return {
        "ok": True,
        "read_only": True,
        "credential_mode": "public-placeholder",
        "item_count": len(targets),
    }
