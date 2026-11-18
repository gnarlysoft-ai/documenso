# Document Signing Certificate

> ## ⚠️ READ THIS FIRST
>
> **Self-signed signatures show as "identity unknown" in Adobe Reader.** PDFs signed with a self-signed cert display in Adobe Reader as *"Signature valid. Signer's identity is UNKNOWN."* Many counterparties — and many internal compliance/legal teams — won't accept signatures with that warning even if the math checks out. Whether a self-signed signature is enforceable in a given jurisdiction is a question for your counsel, not this runbook.
>
> **For high-assurance signing (B2B contracts, regulated workflows), use an AATL cert.** Adobe trusts AATL-rooted signatures by default and displays the signer's identity. See the [AATL attestation matrix](#aatl-attestation-matrix) below to pick a path — the short version is **Azure Key Vault Premium is the cheapest working option (~$850 year 1, ~$350/yr after).** Confirm enforceability and audit requirements with legal/compliance for your jurisdiction.

---

## How signing works here

Documenso signs PDFs using an X.509 certificate whose private key lives in an HSM — AWS KMS, Azure Key Vault, Google Cloud HSM, or a local `.p12` file (depending on the "transport" picked at deploy).

- **The private key stays in the HSM.** No local file, no export. Signing is an API call that hands a digest to the HSM.
- **The certificate** declares "whose public key this is" (subject) and "who vouches for that claim" (issuer).
- **Self-signed** means you are both the subject AND the issuer. No external party vouches. Adobe has no basis to trust.
- **AATL-trusted** means a CA from [Adobe's Approved Trust List](https://helpx.adobe.com/acrobat/kb/approved-trust-list2.html) verified your identity and issued the cert. Adobe trusts their root → your signature chains up to "trusted".

Critically: **you can keep using the same HSM key forever.** Upgrading from self-signed → AATL is just swapping the cert PEM.

---

## AATL attestation matrix

[CABForum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/) (June 2023+) require AATL CAs to attest that the signing key lives in a FIPS 140-2 Level 2+ HSM and was never exported. The HSM backend determines which CA flow is available.

| Backend | Attestation | Cost (first year) | Cost (yearly) | Viability for MSP |
|---|---|---|---|---|
| ❌ **AWS KMS** (standard) | Not supported by any AATL CA — attestation-form audit ($2,000+) required by each CA | Prohibitive | Prohibitive | **No.** Self-signed only. |
| ⚠️ **AWS CloudHSM** | Supported via KGC ceremony | ~$1,600/mo + cert | ~$19,200/yr/deploy | **No.** Too expensive. |
| ✅ **Azure Key Vault Premium** | Built-in via portal CSR. SSL.com + DigiCert + GlobalSign accept. | ~$850 (fee + cert) | ~$350 (cert renewal) | **Yes — recommended.** |
| ✅ **Azure Key Vault Managed HSM** | Same as Premium, but FIPS Level 3 | ~$2,300/mo + fee + cert | Prohibitive | **No.** Premium is cheaper and satisfies AATL. |
| ✅ **Google Cloud HSM** | Built-in attestation | ~$1/mo + cert | Similar to Azure | Viable if already on GCP. |

**Our choice: Azure Key Vault Premium + SSL.com OV Document Signing.** Confirmed via [SSL.com's supported Cloud HSMs guide](https://www.ssl.com/guide/supported-cloud-hsms-document-signing-ev-code-signing/):

- ✅ KV Premium supported
- ✅ Attestation = portal-generated CSR (no separate form)
- ✅ One-time $500 USD attestation fee
- ✅ Base cert tiered by signing volume: Free / +$180 / +$300 / ... per year
- ✅ Key requirement: RSA-HSM, non-exportable, **≥3072 bits**

---

## When self-signed is OK

Use cases where "valid but untrusted identity" is acceptable:

- Internal HR forms, consent flows, approvals within one org
- Demos and UAT environments
- Pilots where counterparties are the same org
- Workflows where the PDF is one artifact among many (e.g. CLM with its own notarization)

**NOT OK:**

- External contracts (clients, vendors, employees outside the org)
- Anything a counterparty's legal team will review
- Anything subject to compliance regimes (SOC 2, HIPAA, FINRA)
- Anything that might end up in discovery during a dispute

---

## Azure Key Vault Premium procurement runbook

Budget: 1-2 business days setup + 3-10 business days for OV validation. Total ~$850 first year, ~$350/yr renewal.

### Prerequisites

- Azure subscription (any tier; subscription ID and tenant ID needed)
- Legal entity in good standing (Articles of Incorporation / Certificate of Good Standing)
- D-U-N-S number — free from [D&B iUpdate](https://iupdate.dnb.com/), takes 1-2 days if you don't have one
- Verifiable business phone number (must appear in public directory — Google Business, D-U-N-S, legal filing)
- Corporate officer's name + government-issued photo ID scan

### Steps 1–3: Provision vault + cert + CSR in one shot

The skill's `scripts/setup-azure-kv.py` does the resource group, Key Vault Premium, attested cert (RSA-HSM 3072 non-exportable, sign + verify), CSR, service principal, and Crypto User role assignment in a single end-to-end run. It writes the CSR to `--csr-out` ready for SSL.com.

```bash
python .claude/skills/deploy-to-aws/scripts/setup-azure-kv.py \
  --profile <azure-auth-profile> \
  --subscription "$AZURE_SUBSCRIPTION_ID" \
  --resource-group documenso-signing-prod \
  --location eastus \
  --vault-name <globally-unique-name> \
  --cert-name documenso-cert \
  --cert-subject 'CN=Your Legal Entity (or verified DBA), O=Your Legal Entity, OU=Documenso, C=US' \
  --cert-email officer@yourdomain.com \
  --csr-out .deploy-artifacts/csr.pem \
  --env-out .deploy.env
```

Requirements on the running profile:

- **Owner** (or equivalent) on the target subscription. The script self-grants Key Vault Certificates Officer on the new vault before calling the cert API, so no pre-existing data-plane access is required.
- If your Owner assignment uses the "Recommended" conditional (Owner/UAA/RBAC excluded), that's fine — Crypto User and Certificates Officer are not in the excluded set.

Manual equivalent if you can't run the script:

```bash
# Resource group + vault
az group create -n documenso-signing-prod -l eastus
az keyvault create -n <vault> -g documenso-signing-prod \
  --sku premium --enable-rbac-authorization true --enable-purge-protection true

# Grant yourself Certificates Officer on the new vault (one-time, ~30s propagation)
az role assignment create --role "Key Vault Certificates Officer" \
  --assignee <your-oid> --scope "/subscriptions/<sub>/resourceGroups/documenso-signing-prod/providers/Microsoft.KeyVault/vaults/<vault>"

# Create the attested pending cert. This atomically creates the RSA-HSM key
# and the pending cert; you cannot pre-create the key separately or you'll
# collide with the cert API (and purge protection blocks reuse for 90 days).
az keyvault certificate create --vault-name <vault> -n documenso-cert \
  --policy "$(cat <<'JSON'
{ "keyProperties": {"keyType":"RSA-HSM","keySize":3072,"exportable":false,"reuseKey":false},
  "secretProperties": {"contentType":"application/x-pem-file"},
  "x509CertificateProperties": {
    "subject":"CN=Your Legal Entity, O=Your Legal Entity, OU=Documenso, C=US",
    "ekus":["1.3.6.1.5.5.7.3.36"],
    "keyUsage":["digitalSignature","nonRepudiation"],
    "validityInMonths":12 },
  "issuerParameters": {"name":"Unknown"}}
JSON
)"

# Download the CSR
az keyvault certificate pending show --vault-name <vault> -n documenso-cert \
  --query csr -o tsv | fold -w 64 | \
  ( echo "-----BEGIN CERTIFICATE REQUEST-----"; cat; echo "-----END CERTIFICATE REQUEST-----" ) \
  > .deploy-artifacts/csr.pem

# Create the ECS service principal with Crypto User scoped to the cert's key
az ad sp create-for-rbac --name documenso-signing-ecs \
  --role "Key Vault Crypto User" \
  --scopes "/subscriptions/<sub>/resourceGroups/documenso-signing-prod/providers/Microsoft.KeyVault/vaults/<vault>/keys/documenso-cert"
```

Important: the cert name **is** the key name in Azure KV — they share the same logical entity. Don't try to create the key separately; the Certificates API owns it.

### Step 4: Order the cert at SSL.com

1. Visit [SSL.com Document Signing Certificates](https://www.ssl.com/certificates/document-signing/).
2. Pick **Organization Validation (OV)**. Pick 1-year or 3-year.
3. During checkout, note under HSM options: **"Azure Key Vault"** — select it. Pay the one-time $500 attestation fee + base cert cost.
4. Upload `csr.pem` when prompted.
5. Upload identity docs: Articles of Incorporation, corporate officer's government ID.
6. Enter signing officer contact info (name, title, business email, business phone).

### Step 5: Respond to SSL.com's validation steps

- SSL.com will call the listed business number (once, 5-min automated) to confirm officer is real.
- May request DUNS lookup confirmation.
- May request a DNS TXT record to prove domain control.

Budget 3-10 business days. Most of the wait is SSL.com's side; respond to their emails within a few hours to keep the clock moving.

### Step 6: Merge the issued cert back into Azure KV

When SSL.com issues the cert, they'll email:
- The issued cert (`.crt` or `.pem`)
- The intermediate + root chain

```bash
# Combine cert + chain into a single PEM (issued first, then intermediates)
cat signing-cert.pem signing-chain.pem > merged-cert.pem

# Merge back into the pending KV certificate. This completes the cert lifecycle
# inside Key Vault — the cert is now bound to the HSM-protected private key.
az keyvault certificate pending merge --vault-name <vault-name> \
  --name documenso-signing-prod \
  --file merged-cert.pem
```

### Step 7: Wire the cert into Documenso's Secrets Manager

```bash
source .deploy.env

# Base64-encode cert + chain
CERT_B64=$(base64 -w0 signing-cert.pem)
CHAIN_B64=$(base64 -w0 signing-chain.pem)

APP_CONFIG_ARN=$(aws cloudformation describe-stacks --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='SecretsAppConfigSecretArn'].OutputValue" --output text)

aws secretsmanager get-secret-value --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --secret-id "$APP_CONFIG_ARN" --query SecretString --output text | \
  jq \
    --arg tenant "$AZURE_KV_TENANT_ID" \
    --arg cid "$AZURE_KV_CLIENT_ID" \
    --arg csec "$AZURE_KV_CLIENT_SECRET" \
    --arg cert "$CERT_B64" \
    --arg chain "$CHAIN_B64" '
      .NEXT_PRIVATE_SIGNING_AZURE_KV_TENANT_ID = $tenant
      | .NEXT_PRIVATE_SIGNING_AZURE_KV_CLIENT_ID = $cid
      | .NEXT_PRIVATE_SIGNING_AZURE_KV_CLIENT_SECRET = $csec
      | .NEXT_PRIVATE_SIGNING_AZURE_KV_PUBLIC_CRT_FILE_CONTENTS = $cert
      | .NEXT_PRIVATE_SIGNING_AZURE_KV_CERT_CHAIN_CONTENTS = $chain
    ' | \
  aws secretsmanager put-secret-value --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --secret-id "$APP_CONFIG_ARN" \
    --secret-string file:///dev/stdin
```

### Step 8: Switch the stack to azure-kv transport

```bash
# Update the stack with SigningTransport=azure-kv + Azure KV coordinates
aws cloudformation update-stack --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" \
  --use-previous-template \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --parameters \
    ParameterKey=SigningTransport,ParameterValue=azure-kv \
    ParameterKey=AzureKvUrl,ParameterValue=https://<vault-name>.vault.azure.net \
    ParameterKey=AzureKvKeyName,ParameterValue=documenso-signing-prod \
    ParameterKey=AzureKvKeyVersion,ParameterValue= \
    ParameterKey=EnvName,UsePreviousValue=true \
    ParameterKey=VpcId,UsePreviousValue=true \
    # ... repeat UsePreviousValue for all other params ...

aws ecs wait services-stable --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --cluster "documenso-$ENV_NAME" --services "documenso-$ENV_NAME"
```

### Step 9: Verify in Adobe Reader

Sign a test doc. Open the signed PDF in Adobe Reader:

- ✅ **Before**: "Signature valid. Signer's identity is UNKNOWN."
- ✅ **After**: Green checkmark. "Signed by [YourOrg]. The signer's identity is valid."

Right-click the signature → **Validate Signature** if Adobe has cached the untrusted result.

---

## MSP Pattern

**Each client needs their own cert, their own Azure KV, their own legal identity.** You cannot use one cert across clients — the cert's subject IS the legal signer, and the $500 attestation fee is per-identity.

For each client deployment:

1. Deploy Documenso into the client's AWS account (this skill).
2. Walk the client through Steps 1-3 above in **their** Azure subscription.
3. Client procures their own SSL.com OV Document Signing cert (they pay the $500 attestation + cert fee, they own it).
4. You can facilitate: generate the CSR, run the merge, wire the secret — but SSL.com verifies the client's identity, not yours.

Cost per client deployment (first year): ~$850 total. ~$350/yr renewal.

**Sub-CA approach?** Becoming a subordinate AATL-approved CA requires WebTrust / ETSI annual audits ($50-100k+), full CA infrastructure, and compliance overhead. Not practical unless you're a dedicated PKI company.

---

## Cert rotation

### Rotating the service principal secret (yearly)

Azure SP secrets expire. Rotate annually:

```bash
# Create new secret, update ECS, retire old secret
NEW_SECRET=$(az ad sp credential reset --id <client-id> --years 1 --query password -o tsv)

# Update app-config with new secret
aws secretsmanager get-secret-value --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --secret-id "$APP_CONFIG_ARN" --query SecretString --output text | \
  jq --arg s "$NEW_SECRET" '.NEXT_PRIVATE_SIGNING_AZURE_KV_CLIENT_SECRET = $s' | \
  aws secretsmanager put-secret-value --profile "$AWS_PROFILE" --region "$AWS_REGION" \
    --secret-id "$APP_CONFIG_ARN" --secret-string file:///dev/stdin

aws ecs update-service --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --cluster "documenso-$ENV_NAME" --service "documenso-$ENV_NAME" \
  --force-new-deployment --no-cli-pager
```

Set a calendar reminder 11 months after the previous rotation.

### Rotating the cert (yearly at expiry)

Same as Steps 3-7 above. **Key stays the same** — only the cert rotates. So no new attestation fee, just the base cert renewal cost (~$180-300/yr depending on signing volume tier).

### Rotating the key (rarely — compromise or policy)

If the HSM-protected key itself needs rotation (e.g. suspected compromise), create a new key version, generate a new CSR, submit to SSL.com as a rekey, and update `NEXT_PRIVATE_SIGNING_AZURE_KV_KEY_VERSION` to pin the new version. Past signatures remain valid (they were signed by the old key; the old cert chain is unchanged).

---

## Inspecting the currently deployed cert

```bash
source .deploy.env
APP_CONFIG_ARN=$(aws cloudformation describe-stacks --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='SecretsAppConfigSecretArn'].OutputValue" --output text)

# Transport-agnostic: extract whichever cert contents are populated
aws secretsmanager get-secret-value --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --secret-id "$APP_CONFIG_ARN" --query SecretString --output text | \
  jq -r '.NEXT_PRIVATE_SIGNING_AZURE_KV_PUBLIC_CRT_FILE_CONTENTS // .NEXT_PRIVATE_SIGNING_AWS_KMS_PUBLIC_CRT_FILE_CONTENTS' | \
  base64 -d | \
  openssl x509 -noout -subject -issuer -dates -fingerprint -sha256
```

- **Issuer matches SSL.com / another AATL CA** → AATL-trusted.
- **Issuer matches your own subject** → self-signed, untrusted by Adobe.

---

## Common mistakes to avoid

1. **Sending real contracts on the self-signed cert** "just for now." The "just for now" contracts become part of your production record.
2. **Picking Azure KV Standard instead of Premium.** Standard SKU has no HSM-backed keys. SSL.com requires Premium. No refunds from Microsoft.
3. **Generating the key with Exportable=true.** Makes the attestation worthless. SSL.com will reject the CSR.
4. **Using a key smaller than 3072 bits.** SSL.com's minimum is 3072. 2048 will be rejected.
5. **Forgetting to merge the CA-issued cert back into Azure KV** (Step 6). The cert is technically usable from Secrets Manager alone (Documenso reads it from there), but having it also in Azure KV keeps the lifecycle aligned with the key.
6. **Losing the Azure SP client-secret.** Recoverable — `az ad sp credential reset --id <client-id>` generates a new one. Update the AWS secret.
7. **Expired cert.** Set a calendar reminder 60 days before expiry. Renewal is cheap (~$180-300) and fast — no new attestation fee.
8. **Assuming AATL = legally binding everywhere.** AATL is an Adobe-specific trust list. Some jurisdictions (EU eIDAS qualified signatures, for example) have additional requirements. Check with counsel for anything cross-border.
