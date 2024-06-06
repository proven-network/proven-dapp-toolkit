import { Pcrs, ProvenDappToolkitOptions, Session, SerializableSession } from './_types'

import { RadixDappToolkit, RadixDappToolkitOptions } from '@radixdlt/radix-dapp-toolkit'
import { decode as cborDecode } from "cbor-x"
import { Sign1 } from "@auth0/cose"
import { X509Certificate, X509ChainBuilder } from "@peculiar/x509"
import { type WalletData } from '@radixdlt/radix-dapp-toolkit'
import elliptic from 'elliptic'
import { areEqualUint8Array, uint8ArrayToHex } from './helpers/uint8array'
import { rootCertificate } from './enclave-root-cert'
import { WebsocketClient } from './websocket/websocket-client'

export type ProvenDappToolkit = {
  pcrs: () => Pcrs | undefined
  ready: () => boolean
  webSocketClient: WebsocketClient
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
  let session: Session | undefined

  const eddsa = new elliptic.eddsa('ed25519')

  const storageKeyPrefix = `prvn:${dAppDefinitionAddress}:${networkId}`
  const sessionStorageKey = `${storageKeyPrefix}:session`

  // Quick hack to purge current session if wallet storage removed or zeroed - must run before RadixDappToolkit init
  const rdtWalletKey = `rdt:${dAppDefinitionAddress}:${networkId}`
  console.log(localStorage.getItem(rdtWalletKey))
  if (localStorage.getItem(rdtWalletKey)) {
    try {
      const state = JSON.parse(localStorage.getItem(rdtWalletKey)!) as { sharedData?: { persona?: { proof?: boolean } } }
      if (!state.sharedData?.persona?.proof) { localStorage.removeItem(sessionStorageKey) }
    } catch (e) { localStorage.removeItem(sessionStorageKey) }
  } else {
    localStorage.removeItem(sessionStorageKey)
  }

  const radixDappToolkit = RadixDappToolkit({
    ...options,
    onDisconnect: () => {
      localStorage.removeItem(sessionStorageKey);

      // TODO: revoke public key on remote server also

      isReady = false
      session = undefined
    }
  })

  if (localStorage.getItem(sessionStorageKey)) {
    const parsedSession = JSON.parse(localStorage.getItem(sessionStorageKey)!) as SerializableSession

    session = {
      ...parsedSession,
      signingKey: eddsa.keyFromSecret(parsedSession.signingKey),
      verifyingKey: eddsa.keyFromPublic(parsedSession.verifyingKey),
    }

    isReady = true
  }

  const provenNetworkHost = {
    2: 'test.weareborderline.com',
  }[networkId]

  if (!provenNetworkHost) {
    throw new Error("Network not supported.")
  }

  const webSocketClient = WebsocketClient({
    eddsa,
    host: provenNetworkHost,
    logger,
    sessionStorageKey,
  })

  const getChallenge: () => Promise<string> = () =>
    fetch(`https://${provenNetworkHost}/create-challenge`)
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

    const newSecretHex = uint8ArrayToHex(crypto.getRandomValues(new Uint8Array(32)))
    const signingKey = eddsa.keyFromSecret(newSecretHex)

    // get bytes from private key
    const publicKeyInput = new Uint8Array(signingKey.getPublic())

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
    const response = await fetch(`https://${provenNetworkHost}/verify`, {
      method: "POST",
      body
    })

    if (!response.ok) {
      throw new Error("Failed to fetch attestation document.")
    }

    const data = new Uint8Array(await response.arrayBuffer())

    // decode COSE elements
    const coseElements = await cborDecode(data) as Uint8Array[]
    const {
      cabundle,
      certificate,
      nonce,
      pcrs: rawPcrs,
      public_key: verifyingKey,
      user_data: sessionId
    } = await cborDecode(coseElements[2]!) as {
      cabundle: Uint8Array[],
      certificate: Uint8Array,
      nonce: Uint8Array,
      pcrs: { [index: number]: Uint8Array },
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
      0: uint8ArrayToHex(rawPcrs[0]!),
      1: uint8ArrayToHex(rawPcrs[1]!),
      2: uint8ArrayToHex(rawPcrs[2]!),
      3: uint8ArrayToHex(rawPcrs[3]!),
      4: uint8ArrayToHex(rawPcrs[4]!),
      8: uint8ArrayToHex(rawPcrs[8]!),
    }

    // verify expected PCRs or throw error
    expectedPcrs && Object.entries(expectedPcrs).forEach(([index, expectedValue]) => {
      if (pcrs[index as unknown as keyof Pcrs] !== expectedValue) {
        throw new Error(`PCR${index} does not match expected value.`)
      }
    })

    isReady = true
    session = {
      sessionId: uint8ArrayToHex(sessionId),
      pcrs,
      signingKey,
      verifyingKey: eddsa.keyFromPublic(uint8ArrayToHex(verifyingKey)),
    }

    // save attested details
    const serializableSession: SerializableSession = {
      sessionId: session.sessionId,
      pcrs: session.pcrs,
      signingKey: session.signingKey.getSecret('hex'),
      verifyingKey: session.verifyingKey.getPublic('hex'),
    }

    localStorage.setItem(sessionStorageKey, JSON.stringify(serializableSession))
  }

  radixDappToolkit.walletApi.dataRequestControl(async ({ proofs }) => {
    fetchAndVerifyAttestation(proofs)
  })

  return [radixDappToolkit, {
    pcrs: () => session?.pcrs,
    ready: () => isReady,
    webSocketClient, // TODO: don't actually expose this in final API
  }]
}
