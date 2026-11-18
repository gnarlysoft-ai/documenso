#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "requests>=2.31",
# ]
# ///
"""
Provision Azure Key Vault Premium for Documenso signing.

Creates (idempotent):
- Resource group
- Key Vault Premium with RBAC, purge protection
- Attested pending certificate via the Azure KV Certificates API
  (creates RSA-HSM 3072-bit non-exportable key + CSR atomically;
  the CA-issued cert merges back via `pending/merge` later)
- Service principal with Key Vault Crypto User role scoped to the cert's key

Also grants the running service principal (from the auth profile) Key Vault
Certificates Officer on the vault so it can call the cert API. Required when
the running SP only has subscription-level Owner (which grants management
plane, not data plane).

Writes the CSR to `--csr-out` as a PEM file ready to attach to the SSL.com
order email.

Appends AZURE_KV_URL, AZURE_KV_KEY_NAME, AZURE_KV_TENANT_ID,
AZURE_KV_CLIENT_ID, AZURE_KV_CLIENT_SECRET to a `.deploy.env` file so the
subsequent CFN deploy can pick them up.

Uses the same auth pattern as the gnarlysoft-microsoft:azure skill's auth.py
(OAuth 2.0 client credentials flow against Microsoft Graph + management API).

Usage:
    python setup-azure-kv.py \\
        --profile <azure-auth-profile> \\
        --subscription <sub-uuid> \\
        --resource-group documenso-signing-prod \\
        --location eastus \\
        --vault-name <globally-unique-name> \\
        --cert-name documenso-cert \\
        --cert-subject 'CN=Your Legal Entity, O=Your Legal Entity, OU=Documenso, C=US' \\
        --cert-email admin@example.com \\
        --csr-out .deploy-artifacts/csr.pem \\
        --env-out .deploy.env
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import requests


AZURE_MGMT = "https://management.azure.com"
# auth.py CLI accepts short scope names: graph, azure, keyvault.
SCOPE_MGMT = "azure"
SCOPE_KV_DATA = "keyvault"
SCOPE_GRAPH = "graph"
API_VERSION_VAULTS = "2023-07-01"
API_VERSION_RBAC = "2022-04-01"
API_VERSION_KV_DATA = "7.4"
KV_CRYPTO_USER_ROLE_ID = "12338af0-0e69-4776-bea7-57ae8d297424"  # Built-in
KV_CERT_OFFICER_ROLE_ID = "a4417e6f-fecd-4de8-b567-7b0420556985"  # Built-in
# RFC 5280 documentSigning EKU. The CA replaces this with its own EKUs on
# issuance — value here is informational, but the policy must declare *some*
# EKU or Azure rejects the policy.
EKU_DOC_SIGNING = "1.3.6.1.5.5.7.3.36"


def get_token(profile: str, scope: str) -> str:
    """Delegate token acquisition to the gnarlysoft-microsoft:azure skill's helper."""
    import subprocess  # nosec
    script_dir = Path.home() / ".claude/plugins/cache/gnarlysoft-plugins/microsoft/1.0.0/scripts"
    if not (script_dir / "auth.py").exists():
        raise RuntimeError(
            f"Azure auth helper not found at {script_dir}. "
            "Install the gnarlysoft-microsoft plugin first."
        )

    result = subprocess.run(  # nosec
        ["uv", "run", "python", "auth.py", "get-token", profile, "--scope", scope],
        cwd=script_dir,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Token fetch failed: {result.stderr}")

    return result.stdout.strip()


def arm_request(
    method: str,
    path: str,
    token: str,
    api_version: str,
    json_body: dict | None = None,
) -> dict[str, Any]:
    """Issue an Azure Resource Manager request with consistent error reporting."""
    url = f"{AZURE_MGMT}{path}"
    separator = "&" if "?" in url else "?"
    url = f"{url}{separator}api-version={api_version}"

    headers = {"Authorization": f"Bearer {token}"}
    if json_body is not None:
        headers["Content-Type"] = "application/json"

    response = requests.request(method, url, headers=headers, json=json_body, timeout=60)

    if not response.ok:
        raise RuntimeError(
            f"{method} {path} failed: {response.status_code} {response.text[:500]}"
        )

    if response.status_code == 204 or not response.content:
        return {}
    return response.json()


def ensure_resource_group(
    token: str, subscription: str, name: str, location: str
) -> None:
    path = f"/subscriptions/{subscription}/resourcegroups/{name}"
    arm_request(
        "PUT", path, token, "2021-04-01", json_body={"location": location}
    )
    print(f"  resource group: {name} (location={location})")


def ensure_key_vault(
    token: str,
    subscription: str,
    resource_group: str,
    name: str,
    location: str,
    tenant_id: str,
) -> dict[str, Any]:
    path = (
        f"/subscriptions/{subscription}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.KeyVault/vaults/{name}"
    )
    body = {
        "location": location,
        "properties": {
            "tenantId": tenant_id,
            "sku": {"family": "A", "name": "premium"},
            "enableRbacAuthorization": True,
            "enableSoftDelete": True,
            "softDeleteRetentionInDays": 90,
            "enablePurgeProtection": True,
            "accessPolicies": [],
        },
    }
    result = arm_request("PUT", path, token, API_VERSION_VAULTS, json_body=body)
    print(f"  key vault: {name} (sku=premium)")
    return result


def get_self_oid(token: str) -> str:
    """Decode the JWT payload and return the 'oid' claim (running SP's object id).

    Avoids an extra Graph round-trip to look up our own identity. JWTs are
    base64url-encoded; we pad and decode the payload segment.
    """
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload))
    return claims["oid"]


def assign_role(
    mgmt_token: str,
    scope: str,
    role_def_id: str,
    principal_oid: str,
    label: str,
) -> None:
    """Assign a built-in role at the given scope, idempotently."""
    subscription = scope.split("/")[2]
    role_def = (
        f"/subscriptions/{subscription}"
        f"/providers/Microsoft.Authorization/roleDefinitions/{role_def_id}"
    )
    assign_id = str(uuid.uuid4())
    path = f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assign_id}"
    body = {
        "properties": {
            "roleDefinitionId": role_def,
            "principalId": principal_oid,
            "principalType": "ServicePrincipal",
        }
    }
    try:
        arm_request("PUT", path, mgmt_token, API_VERSION_RBAC, json_body=body)
        print(f"  role: {label} → {principal_oid} (scope={scope.split('/')[-2]}/{scope.split('/')[-1]})")
    except RuntimeError as exc:
        # Existing assignment for same (scope, role, principal) returns 409.
        if "RoleAssignmentExists" in str(exc) or " 409 " in str(exc):
            print(f"  role: {label} → {principal_oid} (already assigned)")
            return
        raise


def create_pending_cert(
    data_token: str,
    vault_url: str,
    cert_name: str,
    subject: str,
    cert_email: str | None,
) -> str:
    """Use Azure KV Certificates API to create an attested key + pending cert.

    The cert API creates both an RSA-HSM 3072-bit non-exportable key AND a
    pending cert in one atomic call. Pre-creating the key separately would
    collide with this call (purge protection blocks reuse of the name for
    90+ days), so this is the only correct path for the AATL flow.

    Returns the CSR as a PEM string ready to email to the CA. If a pending
    cert already exists with this name, retrieves its CSR instead.
    """
    headers = {
        "Authorization": f"Bearer {data_token}",
        "Content-Type": "application/json",
    }

    pending_url = (
        f"{vault_url}/certificates/{cert_name}/pending?api-version={API_VERSION_KV_DATA}"
    )
    existing = requests.get(pending_url, headers={"Authorization": f"Bearer {data_token}"}, timeout=60)
    if existing.status_code == 200 and existing.json().get("csr"):
        print(f"  certificate: {cert_name} (pending exists, reusing CSR)")
        return _csr_b64_to_pem(existing.json()["csr"])

    sans: dict[str, list[str]] = {}
    if cert_email:
        sans["emails"] = [cert_email]

    body = {
        "policy": {
            "key_props": {
                "kty": "RSA-HSM",
                "key_size": 3072,
                "exportable": False,
                "reuse_key": False,
            },
            "secret_props": {"contentType": "application/x-pem-file"},
            "x509_props": {
                "subject": subject,
                "sans": sans,
                "ekus": [EKU_DOC_SIGNING],
                "key_usage": ["digitalSignature", "nonRepudiation"],
                "validity_months": 12,
            },
            "issuer": {"name": "Unknown"},
        }
    }

    create_url = (
        f"{vault_url}/certificates/{cert_name}/create?api-version={API_VERSION_KV_DATA}"
    )
    response = requests.post(create_url, headers=headers, json=body, timeout=60)
    if not response.ok:
        raise RuntimeError(
            f"Cert create failed: {response.status_code} {response.text[:500]}"
        )

    data = response.json()
    csr_b64 = data.get("csr")
    if not csr_b64:
        raise RuntimeError(f"Cert create response missing 'csr': {data}")

    print(f"  certificate: {cert_name} (RSA-HSM 3072, attested, pending)")
    return _csr_b64_to_pem(csr_b64)


def _csr_b64_to_pem(csr_b64: str) -> str:
    """Wrap an Azure-returned base64 PKCS#10 blob into standard PEM format."""
    lines = ["-----BEGIN CERTIFICATE REQUEST-----"]
    for i in range(0, len(csr_b64), 64):
        lines.append(csr_b64[i : i + 64])
    lines.append("-----END CERTIFICATE REQUEST-----")
    return "\n".join(lines) + "\n"


def _graph_json(response: requests.Response, action: str) -> dict[str, Any]:
    """Return parsed JSON from a Graph response, raising with the response body
    if the call wasn't 2xx (so 401/403/500 surface as clear errors instead of
    KeyError on a missing field)."""
    if not response.ok:
        raise RuntimeError(
            f"Graph API {action} failed: {response.status_code} {response.text[:500]}"
        )
    return response.json()


def create_service_principal(
    graph_token: str, display_name: str
) -> tuple[str, str, str]:
    """Create an Entra app registration + SP; return (app_id, sp_object_id, secret).

    Idempotent on displayName: if one exists, reuse it instead of creating a duplicate.
    """
    list_url = f"https://graph.microsoft.com/v1.0/applications?$filter=displayName eq '{display_name}'"
    headers = {"Authorization": f"Bearer {graph_token}"}
    existing = _graph_json(requests.get(list_url, headers=headers, timeout=60), "list applications")

    if existing.get("value"):
        app = existing["value"][0]
    else:
        create_url = "https://graph.microsoft.com/v1.0/applications"
        app = _graph_json(
            requests.post(
                create_url,
                headers={**headers, "Content-Type": "application/json"},
                json={"displayName": display_name, "signInAudience": "AzureADMyOrg"},
                timeout=60,
            ),
            "create application",
        )

    app_id = app["appId"]

    sp_list = _graph_json(
        requests.get(
            f"https://graph.microsoft.com/v1.0/servicePrincipals?$filter=appId eq '{app_id}'",
            headers=headers,
            timeout=60,
        ),
        "list service principals",
    )
    if sp_list.get("value"):
        sp = sp_list["value"][0]
    else:
        sp = _graph_json(
            requests.post(
                "https://graph.microsoft.com/v1.0/servicePrincipals",
                headers={**headers, "Content-Type": "application/json"},
                json={"appId": app_id},
                timeout=60,
            ),
            "create service principal",
        )

    secret_response = _graph_json(
        requests.post(
            f"https://graph.microsoft.com/v1.0/applications/{app['id']}/addPassword",
            headers={**headers, "Content-Type": "application/json"},
            json={"passwordCredential": {"displayName": f"documenso-{int(time.time())}"}},
            timeout=60,
        ),
        "add password",
    )

    if "secretText" not in secret_response:
        raise RuntimeError(f"Password creation returned no secretText: {secret_response}")

    print(f"  service principal: {display_name} (appId={app_id})")
    return app_id, sp["id"], secret_response["secretText"]


def assign_kv_crypto_user_role(
    mgmt_token: str, vault_resource_id: str, key_name: str, sp_object_id: str
) -> None:
    """Assign 'Key Vault Crypto User' role scoped to the one key."""
    scope = f"{vault_resource_id}/keys/{key_name}"
    assign_role(mgmt_token, scope, KV_CRYPTO_USER_ROLE_ID, sp_object_id, "Key Vault Crypto User")


def assign_kv_cert_officer_to_self(
    mgmt_token: str, vault_resource_id: str, self_oid: str
) -> None:
    """Grant Key Vault Certificates Officer on the vault to the running SP.

    Without this, an Owner-only subscription role can create the vault
    (management plane) but cannot call the Certificates API (data plane,
    requires explicit RBAC role on a vault with `enableRbacAuthorization=true`).
    """
    assign_role(
        mgmt_token,
        vault_resource_id,
        KV_CERT_OFFICER_ROLE_ID,
        self_oid,
        "Key Vault Certificates Officer (self)",
    )


def append_env(env_path: Path, mapping: dict[str, str]) -> None:
    """Append/update key=value pairs in a dotenv file without touching other keys.

    Values are shell-quoted on write (`shlex.quote`) so `source .deploy.env`
    is safe even when values contain `$`, spaces, backticks, or `$(...)` —
    things Azure SP secrets routinely include.

    Existing values are un-quoted (`shlex.split`) before storing so they
    aren't double-quoted on a subsequent run.
    """
    existing: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                raw = value.strip()
                try:
                    parsed = shlex.split(raw, posix=True)
                    existing[key.strip()] = parsed[0] if parsed else ""
                except ValueError:
                    # Mismatched quotes etc. — keep raw so we don't lose data,
                    # and downstream shlex.quote will escape it on write.
                    existing[key.strip()] = raw

    existing.update(mapping)

    lines = [f"{k}={shlex.quote(v)}" for k, v in existing.items()]
    env_path.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", required=True, help="Azure auth profile name")
    parser.add_argument("--subscription", required=True, help="Azure subscription UUID")
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--location", default="eastus")
    parser.add_argument(
        "--vault-name",
        required=True,
        help="Must be globally unique; Azure KV names are 3-24 alphanumeric characters",
    )
    parser.add_argument(
        "--cert-name",
        required=True,
        help="Azure KV certificate name; also becomes the key name (RSA-HSM key the cert is bound to)",
    )
    parser.add_argument(
        "--cert-subject",
        required=True,
        help='X.500 subject DN, e.g. \'CN=Acme Inc, O=Acme Inc, OU=Documenso, C=US\'. '
        'For values containing commas, wrap in quotes: O="Acme, Inc.".',
    )
    parser.add_argument(
        "--cert-email",
        default=None,
        help="Email address to include as subjectAltName in the CSR (recommended for OV doc signing)",
    )
    parser.add_argument(
        "--csr-out",
        default=".deploy-artifacts/csr.pem",
        help="Path to write the generated CSR PEM (attach this to the SSL.com order email)",
    )
    parser.add_argument("--env-out", default=".deploy.env")
    parser.add_argument(
        "--sp-name",
        default=None,
        help="Service principal displayName (default: documenso-signing-ecs-<rg>)",
    )
    args = parser.parse_args()

    sp_name = args.sp_name or f"documenso-signing-ecs-{args.resource_group}"
    vault_url = f"https://{args.vault_name}.vault.azure.net"

    print("Fetching Azure tokens...")
    mgmt_token = get_token(args.profile, SCOPE_MGMT)
    kv_data_token = get_token(args.profile, SCOPE_KV_DATA)
    graph_token = get_token(args.profile, SCOPE_GRAPH)

    self_oid = get_self_oid(mgmt_token)

    sub_info = arm_request(
        "GET", f"/subscriptions/{args.subscription}", mgmt_token, "2022-12-01"
    )
    tenant_id = sub_info["tenantId"]

    print(f"\nProvisioning in subscription {args.subscription} (tenant {tenant_id}):")
    ensure_resource_group(mgmt_token, args.subscription, args.resource_group, args.location)
    vault = ensure_key_vault(
        mgmt_token,
        args.subscription,
        args.resource_group,
        args.vault_name,
        args.location,
        tenant_id,
    )

    # Grant the running SP data-plane access to the new vault BEFORE we try to
    # call the cert API. Owner on the subscription is management-plane only.
    assign_kv_cert_officer_to_self(mgmt_token, vault["id"], self_oid)

    print("  waiting 30s for vault + role assignment propagation...")
    time.sleep(30)

    csr_pem = create_pending_cert(
        kv_data_token,
        vault_url,
        args.cert_name,
        args.cert_subject,
        args.cert_email,
    )

    csr_path = Path(args.csr_out)
    csr_path.parent.mkdir(parents=True, exist_ok=True)
    csr_path.write_text(csr_pem)
    print(f"  CSR written to: {csr_path}")

    app_id, sp_object_id, client_secret = create_service_principal(graph_token, sp_name)

    assign_kv_crypto_user_role(
        mgmt_token,
        vault["id"],
        args.cert_name,
        sp_object_id,
    )

    env_updates = {
        "AZURE_SUBSCRIPTION_ID": args.subscription,
        "AZURE_KV_URL": vault_url,
        "AZURE_KV_VAULT_NAME": args.vault_name,
        # Cert and underlying key share a name in Azure KV; keep the env var
        # name AZURE_KV_KEY_NAME so downstream config wiring is unchanged.
        "AZURE_KV_KEY_NAME": args.cert_name,
        "AZURE_KV_TENANT_ID": tenant_id,
        "AZURE_KV_CLIENT_ID": app_id,
        "AZURE_KV_CLIENT_SECRET": client_secret,
    }

    append_env(Path(args.env_out), env_updates)

    print(f"\n✓ Azure KV provisioning complete. Values written to {args.env_out}:")
    for key in env_updates:
        masked = "***" if "SECRET" in key else env_updates[key]
        print(f"  {key}={masked}")

    print(
        f"\nNext: attach {csr_path} to your SSL.com order email. "
        f"When the issued cert + chain arrive, merge with:\n"
        f"  az keyvault certificate pending merge "
        f"--vault-name {args.vault_name} --name {args.cert_name} "
        f"--file <(cat issued-cert.pem chain.pem)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
