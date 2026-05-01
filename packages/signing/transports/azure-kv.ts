import { parsePem } from '@libpdf/core';
import fs from 'node:fs';

import { env } from '@documenso/lib/utils/env';

import { AzureKvSigner } from '../lib/azure-kv-signer';

const loadCertificates = async (
  vaultUrl: string,
  credentials: { tenantId?: string; clientId?: string; clientSecret?: string },
): Promise<Uint8Array[]> => {
  const certContents = env('NEXT_PRIVATE_SIGNING_AZURE_KV_PUBLIC_CRT_FILE_CONTENTS');
  const certFilePath = env('NEXT_PRIVATE_SIGNING_AZURE_KV_PUBLIC_CRT_FILE_PATH');
  const chainContents = env('NEXT_PRIVATE_SIGNING_AZURE_KV_CERT_CHAIN_CONTENTS');
  const chainFilePath = env('NEXT_PRIVATE_SIGNING_AZURE_KV_CERT_CHAIN_FILE_PATH');

  const readPemBlocks = (input: string): Uint8Array[] => parsePem(input).map((block) => block.der);

  if (certContents || certFilePath) {
    const leafPem = certContents
      ? Buffer.from(certContents, 'base64').toString('utf-8')
      : fs.readFileSync(certFilePath as string).toString('utf-8');
    const leafBlocks = readPemBlocks(leafPem);

    if (leafBlocks.length === 0) {
      throw new Error('NEXT_PRIVATE_SIGNING_AZURE_KV_PUBLIC_CRT_FILE_CONTENTS is empty');
    }

    const chainBlocks: Uint8Array[] = [];

    if (chainContents) {
      chainBlocks.push(...readPemBlocks(Buffer.from(chainContents, 'base64').toString('utf-8')));
    } else if (chainFilePath) {
      chainBlocks.push(...readPemBlocks(fs.readFileSync(chainFilePath).toString('utf-8')));
    }

    // If a single bundle was pasted into PUBLIC_CRT_FILE_CONTENTS, leafBlocks already
    // contains [leaf, ...chain] — pass it through. Otherwise leafBlocks is just [leaf]
    // and we append the explicit chain.
    return leafBlocks.length > 1 ? leafBlocks : [leafBlocks[0], ...chainBlocks];
  }

  // Last-resort: Azure Key Vault Certificates / Secrets API, living in the same vault.
  const vaultCertName = env('NEXT_PRIVATE_SIGNING_AZURE_KV_CERT_NAME');

  if (vaultCertName) {
    const { cert, chain } = await AzureKvSigner.getCertificateFromVault(vaultUrl, vaultCertName, {
      credentials,
    });

    if (chain) {
      return [cert, ...chain];
    }

    return [cert];
  }

  throw new Error('No certificate found for Azure Key Vault signing');
};

export const createAzureKvSigner = async () => {
  const vaultUrl = env('NEXT_PRIVATE_SIGNING_AZURE_KV_URL');

  if (!vaultUrl) {
    throw new Error(
      'NEXT_PRIVATE_SIGNING_AZURE_KV_URL is required for Azure Key Vault signing ' +
        '(e.g. https://<vault>.vault.azure.net)',
    );
  }

  const keyName = env('NEXT_PRIVATE_SIGNING_AZURE_KV_KEY_NAME');

  if (!keyName) {
    throw new Error(
      'NEXT_PRIVATE_SIGNING_AZURE_KV_KEY_NAME is required for Azure Key Vault signing',
    );
  }

  const keyVersion = env('NEXT_PRIVATE_SIGNING_AZURE_KV_KEY_VERSION') || undefined;

  const credentials = {
    tenantId: env('NEXT_PRIVATE_SIGNING_AZURE_KV_TENANT_ID'),
    clientId: env('NEXT_PRIVATE_SIGNING_AZURE_KV_CLIENT_ID'),
    clientSecret: env('NEXT_PRIVATE_SIGNING_AZURE_KV_CLIENT_SECRET'),
  };

  const signingAlgorithm = env('NEXT_PRIVATE_SIGNING_AZURE_KV_ALGORITHM') || undefined;

  const certs = await loadCertificates(vaultUrl, credentials);

  if (certs.length === 0) {
    throw new Error('No valid certificates found for Azure Key Vault signing');
  }

  return AzureKvSigner.create({
    vaultUrl,
    keyName,
    keyVersion,
    signingAlgorithm,
    credentials,
    certificate: certs[0],
    certificateChain: certs.length > 1 ? certs.slice(1) : undefined,
  });
};
