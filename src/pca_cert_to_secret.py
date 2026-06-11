"""
Lambda function to issue TLS certificates from AWS Private CA and store them
in AWS Secrets Manager, triggered by both Secrets Manager rotation events and
a manual test event for initial issuance.

Secret JSON structure (defined here, consumed by EC2 userdata):
{
    "private_key":         "<PEM-encoded RSA private key>",
    "certificate":         "<PEM-encoded end-entity certificate>",
    "certificate_chain":   "<PEM-encoded CA chain (intermediates + root)>",
    "common_name":         "<CN used when issuing>",
    "sans":                ["<DNS SAN 1>", "<DNS SAN 2>", ...],
    "serial_number":       "<hex serial number of the issued certificate>",
    "issuer":              "<RFC 4514 distinguished name of the issuing CA>",
    "issued_at":           "<ISO-8601 UTC timestamp>",
    "expires_at":          "<ISO-8601 UTC timestamp>"
}

Trigger modes
-------------
Secrets Manager rotation  →  event contains SecretId, ClientRequestToken, Step
Manual test / initial     →  event contains:
    {
        "action":    "create_initial",
        "SecretId":  "<secret ARN or name>",
        "sans":      ["alt1.example.com", "alt2.example.com"]   # optional
    }

Required Lambda environment variables
--------------------------------------
PCA_ARN       - ACM PCA ARN to use for issuance
COMMON_NAME   - CN for the certificate subject

Optional Lambda environment variables
--------------------------------------
SANS          - comma-separated DNS SANs added to every rotation-issued cert
                e.g. "www.example.com,api.example.com"
                SANs supplied in a manual test event override this value.
VALIDITY_DAYS - certificate validity in days (default: 365)
LOG_LEVEL     - DEBUG / INFO / WARNING / ERROR (default: INFO)

Example test event (initial / manual issuance)
----------------------------------------------
{
    "action":   "create_initial",
    "SecretId": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-tls-cert",
    "sans":     ["www.example.com", "api.example.com"]
}

To trigger without SANs (CN only), omit the "sans" key or pass an empty list:
{
    "action":   "create_initial",
    "SecretId": "arn:aws:secretsmanager:us-east-1:123456789012:secret:my-tls-cert"
}
"""

import collections
import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


###
# Logging
###

DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVELS = collections.defaultdict(
    lambda: DEFAULT_LOG_LEVEL,
    {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    },
)

root = logging.getLogger()
for _h in root.handlers:
    root.removeHandler(_h)

logging.basicConfig(
    format=(
        "%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)s]: %(message)s"
    ),
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=LOG_LEVELS[os.environ.get("LOG_LEVEL", "").upper()],
)
log = logging.getLogger(__name__)


###
# Environment / constants
###

PCA_ARN = os.environ["PCA_ARN"]
COMMON_NAME = os.environ["COMMON_NAME"]
VALIDITY_DAYS = int(os.getenv("VALIDITY_DAYS", "365"))

# Comma-separated DNS SANs applied to every rotation-triggered issuance.
# Individual test events may override this via the "sans" event key.
_SANS_ENV = [
    s.strip()
    for s in os.getenv("SANS", "").split(",")
    if s.strip()
]

# Maximum poll iterations (2 s sleep each → up to 120 s)
CERT_POLL_MAX_ATTEMPTS = 60
CERT_POLL_SLEEP_SECONDS = 2


###
# AWS clients (module-level so Lambda can reuse across warm invocations)
###

secretsmanager = boto3.client("secretsmanager")
acmpca = boto3.client("acm-pca")


###
# Handler
###

def lambda_handler(event, context):
    """
    Entry point.

    Handles two event shapes:
    1. Secrets Manager rotation event  - four-step rotation lifecycle
    2. Manual / test event             - {"action": "create_initial",
                                          "SecretId": "<arn-or-name>"}
    """
    log.info("Lambda ARN: %s", context.invoked_function_arn)
    log.debug("Event: %s", json.dumps(event))

    # ------------------------------------------------------------------
    # Manual / initial-creation path
    # ------------------------------------------------------------------
    if event.get("action") == "create_initial":
        secret_id = event.get("SecretId")
        if not secret_id:
            raise ValueError(
                "Manual event must include 'SecretId'"
            )
        # SANs from the event override the environment variable
        sans = event.get("sans") or _SANS_ENV
        log.info(
            "Manual create_initial triggered for secret: %s  SANs: %s",
            secret_id,
            sans,
        )
        _initial_create(secret_id, sans)
        return

    # ------------------------------------------------------------------
    # Secrets Manager rotation path
    # ------------------------------------------------------------------
    arn = event["SecretId"]
    token = event["ClientRequestToken"]
    step = event["Step"]

    log.info(
        "Rotation event - SecretId: %s  Step: %s  Token: %s",
        arn,
        step,
        token,
    )

    try:
        metadata = secretsmanager.describe_secret(SecretId=arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        log.error("describe_secret failed (%s): %s", code, exc)
        raise

    if not metadata.get("RotationEnabled"):
        log.error("Rotation is not enabled for secret %s", arn)
        raise ValueError(
            f"Secret {arn} is not enabled for rotation"
        )

    versions = metadata["VersionIdsToStages"]

    if token not in versions:
        log.error(
            "Version %s has no stage for secret %s", token, arn
        )
        raise ValueError(
            f"Secret version {token} has no stage for secret {arn}"
        )

    if "AWSCURRENT" in versions[token]:
        log.info(
            "Version %s is already AWSCURRENT for %s - nothing to do",
            token,
            arn,
        )
        return

    if "AWSPENDING" not in versions[token]:
        log.error(
            "Version %s is not AWSPENDING for secret %s", token, arn
        )
        raise ValueError(
            f"Version {token} is not AWSPENDING for secret {arn}"
        )

    if step == "createSecret":
        create_secret(arn, token)
    elif step == "setSecret":
        set_secret(arn, token)
    elif step == "testSecret":
        test_secret(arn, token)
    elif step == "finishSecret":
        finish_secret(arn, token)
    else:
        raise ValueError(f"Unknown rotation step: {step}")


###
# Rotation steps
###

def create_secret(secret_arn, token):
    """
    Step 1 - generate a new key pair, issue a certificate via ACM PCA,
    and store the bundle as AWSPENDING.
    """
    stages = _get_version_stages(secret_arn, token)

    if "AWSPENDING" in stages:
        log.info(
            "createSecret: AWSPENDING already exists for %s - skipping",
            secret_arn,
        )
        return

    log.info("createSecret: generating key and issuing certificate")
    payload = _issue_certificate(_SANS_ENV)

    try:
        secretsmanager.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=json.dumps(payload),
            VersionStages=["AWSPENDING"],
        )
    except ClientError as exc:
        log.error("createSecret: put_secret_value failed: %s", exc)
        raise

    log.info(
        "createSecret: AWSPENDING written for %s (expires %s)",
        secret_arn,
        payload["expires_at"],
    )


def set_secret(secret_arn, token):
    """
    Step 2 - push the new certificate to any dependent service.

    Because EC2 instances pull the certificate directly from Secrets Manager
    via userdata / a reload script, no active push is required here.
    If you add SSM-based push logic in the future, do it in this function.
    """
    log.info(
        "setSecret: no active push required - EC2 pulls from Secrets "
        "Manager directly; continuing"
    )


def test_secret(secret_arn, token):
    """
    Step 3 - validate the AWSPENDING secret is internally consistent.

    Checks:
    - Private key and certificate public keys match
    - Certificate has not already expired
    - Certificate chain is present
    - Common name in the secret matches COMMON_NAME env var
    """
    log.info("testSecret: validating AWSPENDING for %s", secret_arn)
    secret = _get_secret_dict(secret_arn, "AWSPENDING", token)

    # Validate expected keys are present
    _validate_secret_structure(secret)

    cert = x509.load_pem_x509_certificate(
        secret["certificate"].encode()
    )
    private_key = serialization.load_pem_private_key(
        secret["private_key"].encode(),
        password=None,
    )

    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if cert_pub != key_pub:
        raise ValueError(
            "testSecret: certificate public key does not match private key"
        )

    if cert.not_valid_after_utc <= datetime.now(timezone.utc):
        raise ValueError("testSecret: certificate has already expired")

    if not secret.get("certificate_chain"):
        raise ValueError("testSecret: certificate chain is missing")

    if secret.get("common_name") != COMMON_NAME:
        log.warning(
            "testSecret: common_name in secret (%s) differs from "
            "COMMON_NAME env var (%s)",
            secret.get("common_name"),
            COMMON_NAME,
        )

    # Verify serial number in the secret matches the parsed certificate
    expected_serial = format(cert.serial_number, "x")
    if secret.get("serial_number") != expected_serial:
        raise ValueError(
            f"testSecret: serial_number mismatch - "
            f"secret has '{secret.get('serial_number')}', "
            f"certificate has '{expected_serial}'"
        )

    log.info("testSecret: AWSPENDING validated successfully for %s", secret_arn)


def finish_secret(secret_arn, token):
    """
    Step 4 - promote AWSPENDING to AWSCURRENT.
    """
    metadata = secretsmanager.describe_secret(SecretId=secret_arn)
    current_version = None

    for version, stages in metadata["VersionIdsToStages"].items():
        if "AWSCURRENT" in stages:
            current_version = version
            break

    if current_version == token:
        log.info(
            "finishSecret: version %s is already AWSCURRENT for %s",
            token,
            secret_arn,
        )
        return

    secretsmanager.update_secret_version_stage(
        SecretId=secret_arn,
        VersionStage="AWSCURRENT",
        MoveToVersionId=token,
        RemoveFromVersionId=current_version,
    )
    log.info(
        "finishSecret: promoted version %s to AWSCURRENT for %s",
        token,
        secret_arn,
    )


###
# Manual / initial creation (no rotation token)
###

def _initial_create(secret_id, sans=None):
    """
    Issue a certificate and overwrite the secret's AWSCURRENT value directly.
    Intended for the very first run (test event) when no rotation token exists.
    The secret must already exist in Secrets Manager (created externally via
    Terraform).
    """
    payload = _issue_certificate(sans or [])

    try:
        secretsmanager.put_secret_value(
            SecretId=secret_id,
            SecretString=json.dumps(payload),
            VersionStages=["AWSCURRENT"],
        )
    except ClientError as exc:
        log.error("_initial_create: put_secret_value failed: %s", exc)
        raise

    log.info(
        "_initial_create: certificate stored in %s  serial=%s  expires=%s",
        secret_id,
        payload["serial_number"],
        payload["expires_at"],
    )


###
# Core certificate issuance
###

def _issue_certificate(sans=None):
    """
    Generate an RSA key pair, issue a certificate from ACM PCA, and return
    the secret payload dict.

    Args:
        sans: list of DNS SAN strings to include (may be empty or None)

    Returns:
        dict with keys:
            private_key, certificate, certificate_chain,
            common_name, sans, serial_number, issuer,
            issued_at, expires_at
    """
    sans = sans or []

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME)
            ])
        )
    )

    # Add SAN extension when DNS names are provided
    if sans:
        csr_builder = csr_builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in sans]
            ),
            critical=False,
        )
        log.debug("Adding SANs to CSR: %s", sans)

    csr = csr_builder.sign(private_key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    log.debug("Submitting CSR to PCA: %s", PCA_ARN)
    try:
        response = acmpca.issue_certificate(
            CertificateAuthorityArn=PCA_ARN,
            Csr=csr_pem,
            SigningAlgorithm="SHA256WITHRSA",
            Validity={
                "Type": "DAYS",
                "Value": VALIDITY_DAYS,
            },
        )
    except ClientError as exc:
        log.error("issue_certificate failed: %s", exc)
        raise

    cert_arn = response["CertificateArn"]
    log.info("Certificate ARN: %s - waiting for issuance", cert_arn)

    certificate_pem, chain_pem = _wait_for_certificate(cert_arn)

    parsed = x509.load_pem_x509_certificate(certificate_pem.encode())

    # Extract serial number as zero-padded hex (colon-separated pairs)
    serial_hex = format(parsed.serial_number, "x")

    # Extract issuer as RFC 4514 string (e.g. "CN=My CA,O=Example,C=US")
    issuer_str = parsed.issuer.rfc4514_string()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    return {
        "private_key": private_key_pem,
        "certificate": certificate_pem,
        "certificate_chain": chain_pem,
        "common_name": COMMON_NAME,
        "sans": sans,
        "serial_number": serial_hex,
        "issuer": issuer_str,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": parsed.not_valid_after_utc.isoformat(),
    }


def _wait_for_certificate(certificate_arn):
    """
    Poll ACM PCA until the certificate is ready.

    Returns:
        (certificate_pem, chain_pem) as strings
    Raises:
        TimeoutError if the certificate is not issued within the poll window
    """
    for attempt in range(1, CERT_POLL_MAX_ATTEMPTS + 1):
        try:
            result = acmpca.get_certificate(
                CertificateAuthorityArn=PCA_ARN,
                CertificateArn=certificate_arn,
            )
            log.info("Certificate ready after %d poll(s)", attempt)
            return result["Certificate"], result["CertificateChain"]

        except acmpca.exceptions.RequestInProgressException:
            log.debug(
                "Certificate not ready yet (attempt %d/%d) - waiting %ds",
                attempt,
                CERT_POLL_MAX_ATTEMPTS,
                CERT_POLL_SLEEP_SECONDS,
            )
            time.sleep(CERT_POLL_SLEEP_SECONDS)

        except ClientError as exc:
            log.error("get_certificate failed: %s", exc)
            raise

    raise TimeoutError(
        f"Timed out waiting for certificate {certificate_arn} after "
        f"{CERT_POLL_MAX_ATTEMPTS * CERT_POLL_SLEEP_SECONDS}s"
    )


###
# Helpers
###

def _get_secret_dict(secret_arn, stage, token=None):
    """
    Retrieve and parse the JSON secret for the given stage.

    Args:
        secret_arn: Secret ARN or name
        stage:      AWSCURRENT or AWSPENDING
        token:      Version ID (required when fetching AWSPENDING)

    Returns:
        dict parsed from SecretString
    """
    kwargs = {
        "SecretId": secret_arn,
        "VersionStage": stage,
    }
    if token:
        kwargs["VersionId"] = token

    try:
        response = secretsmanager.get_secret_value(**kwargs)
    except ClientError as exc:
        log.error(
            "_get_secret_dict: get_secret_value failed for %s/%s: %s",
            secret_arn,
            stage,
            exc,
        )
        raise

    try:
        return json.loads(response["SecretString"])
    except (json.JSONDecodeError, KeyError) as exc:
        log.error(
            "_get_secret_dict: invalid JSON in secret %s", secret_arn
        )
        raise ValueError(
            f"Invalid JSON in secret {secret_arn}"
        ) from exc


def _get_version_stages(secret_arn, token):
    """Return the list of stages for the given version token."""
    try:
        metadata = secretsmanager.describe_secret(SecretId=secret_arn)
    except ClientError as exc:
        log.error(
            "_get_version_stages: describe_secret failed: %s", exc
        )
        raise
    return metadata["VersionIdsToStages"].get(token, [])


def _validate_secret_structure(secret):
    """
    Raise ValueError if any required key is missing from the secret dict.

    Required keys align with the secret structure documented at the top of
    this file and expected by EC2 userdata.
    """
    required = {
        "private_key",
        "certificate",
        "certificate_chain",
        "common_name",
        "sans",
        "serial_number",
        "issuer",
        "issued_at",
        "expires_at",
    }
    missing = required - set(secret.keys())
    if missing:
        raise ValueError(
            f"Secret is missing required keys: {missing}"
        )
