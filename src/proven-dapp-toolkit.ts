import { Pcrs, ProvenDappToolkitOptions } from './_types'

import { RadixDappToolkit, RadixDappToolkitOptions } from '@radixdlt/radix-dapp-toolkit'
import * as cbor from "cbor-web"
import { Sign1 } from "@auth0/cose"
import { X509Certificate, X509ChainBuilder } from "@peculiar/x509"
import { type WalletData } from '@radixdlt/radix-dapp-toolkit'
import elliptic from 'elliptic'
import { areEqualUint8Array, hexToUint8Array, uint8ArrayToHex } from './helpers/uint8array'
import { rootCertificate } from './enclave-root-cert'

export type ProvenDappToolkit = {
  pcrs: () => Pcrs | undefined
  ready: () => boolean
}

export const ProvenDappToolkit = (
  options: RadixDappToolkitOptions & ProvenDappToolkitOptions,
): [RadixDappToolkit, ProvenDappToolkit] => {
  const {
    applicationName,
    dAppDefinitionAddress,
    expectedPcrs,
    logger,
    networkId,
  } = options || {}

  let isReady: boolean = false
  // @ts-ignore: Unreachable code error
  let attestedSessionId: Uint8Array | undefined
  let attestedPcrs: Pcrs | undefined
  // @ts-ignore: Unreachable code error
  let attestedVerifyingKey: elliptic.eddsa.KeyPair | undefined

  const ec = new elliptic.eddsa('ed25519')

  const storageKeyPrefix = `prvn:${dAppDefinitionAddress}:${networkId}`
  const sessionIdStorageKey = `${storageKeyPrefix}:session_id`
  const signingKeyStorageKey = `${storageKeyPrefix}:signing_key`
  const pcrsStorageKey = `${storageKeyPrefix}:pcrs`
  const verifyingKeyStorageKey = `${storageKeyPrefix}:verifying_key`

  let keyPair: elliptic.eddsa.KeyPair

  const refreshSigningKey = () => {
    if (localStorage.getItem(signingKeyStorageKey)) {
      keyPair = ec.keyFromSecret(localStorage.getItem(signingKeyStorageKey)!)
    } else {
      const newSecretHex = uint8ArrayToHex(crypto.getRandomValues(new Uint8Array(32)))
      keyPair = ec.keyFromSecret(newSecretHex)
      localStorage.setItem(signingKeyStorageKey, newSecretHex)
    }
  }

  refreshSigningKey()

  const radixDappToolkit = RadixDappToolkit({
    ...options,
    onDisconnect: () => {
      localStorage.removeItem(signingKeyStorageKey);
      localStorage.removeItem(pcrsStorageKey);
      localStorage.removeItem(sessionIdStorageKey);
      localStorage.removeItem(verifyingKeyStorageKey);

      // TODO: revoke public key on remote server also

      isReady = false
      refreshSigningKey()
      attestedPcrs = undefined
    }
  })

  if (!!radixDappToolkit.walletApi.getWalletData().persona
    && localStorage.getItem(pcrsStorageKey)
    && localStorage.getItem(sessionIdStorageKey)
    && localStorage.getItem(verifyingKeyStorageKey)
  ) {
    attestedPcrs = JSON.parse(localStorage.getItem(pcrsStorageKey)!)
    attestedSessionId = hexToUint8Array(localStorage.getItem(sessionIdStorageKey)!)
    attestedVerifyingKey = ec.keyFromPublic(localStorage.getItem(verifyingKeyStorageKey)!)
    isReady = true
  } else {
    // remove all existing data if persona not present or missing any attested data
    localStorage.removeItem(pcrsStorageKey)
    localStorage.removeItem(sessionIdStorageKey)
    localStorage.removeItem(verifyingKeyStorageKey)
  }

  const provenNetworkOrigin = {
    2: 'https://test.weareborderline.com',
  }[networkId]

  const getChallenge: () => Promise<string> = () =>
    fetch(`${provenNetworkOrigin}/create-challenge`)
      .then((res) => res.text())

  radixDappToolkit.walletApi.provideChallengeGenerator(getChallenge)

  const fetchAndVerifyAttestation = async (proofs: WalletData['proofs']) => {
    const personaProofs = proofs.filter(({ type }) => type === 'persona')

    if (personaProofs.length === 0) {
      logger?.debug("No persona proofs found. Use `.withProof()` on persona data request to enable Proven.")
    }

    if (personaProofs.length > 1) {
      throw new Error("Multiple persona proofs found. Only one is allowed.")
    }

    // get bytes from private key
    const publicKeyInput = new Uint8Array(keyPair.getPublic())

    // generate nonce to verify in response
    const nonceInput = new Uint8Array(32)
    crypto.getRandomValues(nonceInput)

    const body = new FormData()
    body.append("public_key", new Blob([publicKeyInput], { type: 'application/octet-stream' }))
    body.append("nonce", new Blob([nonceInput], { type: 'application/octet-stream' }))
    body.append("signed_challenge", new Blob([JSON.stringify(proofs)], { type: 'application/json' }))
    body.append("dapp_definition_address", dAppDefinitionAddress)
    if (applicationName) body.append("application_name", applicationName)

    // send attestation request
    const response = await fetch(`${provenNetworkOrigin}/verify`, {
      method: "POST",
      body
    })

    if (!response.ok) {
      throw new Error("Failed to fetch attestation document.")
    }

    const data = new Uint8Array(await response.arrayBuffer())

    // decode COSE elements
    const coseElements = await cbor.decodeFirst(data) as Uint8Array[]
    const {
      cabundle,
      certificate,
      nonce,
      pcrs: rawPcrs,
      public_key: verifyingKey,
      user_data: sessionId
    } = await cbor.decodeFirst(coseElements[2]!) as {
      cabundle: Uint8Array[],
      certificate: Uint8Array,
      nonce: Uint8Array,
      pcrs: Map<number, Uint8Array>,
      public_key: Uint8Array,
      user_data: Uint8Array
    }
    const leaf = new X509Certificate(certificate)

    // verify nonce or throw error
    if (!areEqualUint8Array(nonceInput, nonce)) {
      throw new Error("Attestation nonce does not match expected value.")
    }

    // verify leaf still valid or throw error
    if (leaf.notAfter < new Date()) {
      throw new Error("Attestation document certificate has expired.")
    }

    // verify cose sign1 or throw error
    const publicKey = await crypto.subtle.importKey('spki', new Uint8Array(leaf.publicKey.rawData), { name: 'ECDSA', namedCurve: 'P-384' }, true, ['verify'])
    await Sign1.decode(data).verify(publicKey)

    // verify certificate chain or throw error
    const knownCa = new X509Certificate(rootCertificate)
    const chain = await new X509ChainBuilder({
      certificates: cabundle.map((cert) => new X509Certificate(cert)),
    }).build(leaf)
    if (!chain[chain.length - 1]?.equal(knownCa)) {
      throw new Error("x509 certificate chain does not have expected certificate authority.")
    }

    const pcrs: Pcrs = {
      0: uint8ArrayToHex(rawPcrs.get(0)!),
      1: uint8ArrayToHex(rawPcrs.get(1)!),
      2: uint8ArrayToHex(rawPcrs.get(2)!),
      3: uint8ArrayToHex(rawPcrs.get(3)!),
      4: uint8ArrayToHex(rawPcrs.get(4)!),
      8: uint8ArrayToHex(rawPcrs.get(8)!),
    }

    // verify expected PCRs or throw error
    expectedPcrs && Object.entries(expectedPcrs).forEach(([index, expectedValue]) => {
      if (pcrs[index as unknown as keyof Pcrs] !== expectedValue) {
        throw new Error(`PCR${index} does not match expected value.`)
      }
    })

    // save verified details
    localStorage.setItem(sessionIdStorageKey, uint8ArrayToHex(sessionId))
    localStorage.setItem(pcrsStorageKey, JSON.stringify(pcrs))
    localStorage.setItem(verifyingKeyStorageKey, uint8ArrayToHex(verifyingKey))

    isReady = true

    attestedPcrs = pcrs
    attestedSessionId = sessionId
    attestedVerifyingKey = ec.keyFromPublic(uint8ArrayToHex(verifyingKey))
  }

  radixDappToolkit.walletApi.dataRequestControl(async ({ proofs }) => {
    fetchAndVerifyAttestation(proofs)
  })

  return [radixDappToolkit, {
    pcrs: () => attestedPcrs,
    ready: () => isReady,
  }]
}
