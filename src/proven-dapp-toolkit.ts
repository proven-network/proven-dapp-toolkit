import { Pcrs, ProvenDappToolkitOptions } from './_types'

import { RadixDappToolkit, RadixDappToolkitOptions } from '@radixdlt/radix-dapp-toolkit'
import * as cbor from "cbor-web"
import { Sign1 } from "@auth0/cose"
import { X509Certificate, X509ChainBuilder } from "@peculiar/x509"
import { type WalletData } from '@radixdlt/radix-dapp-toolkit'
import elliptic from 'elliptic'
import { uint8ArrayToHex, areEqualUint8Array } from './helpers/uint8array'
import { rootCertificate } from './enclave-root-cert'

export type ProvenDappToolkit = {
  pcrs: () => Pcrs | undefined
  ready: () => boolean
}

export const ProvenDappToolkit = (
  options: RadixDappToolkitOptions & ProvenDappToolkitOptions,
): [RadixDappToolkit, ProvenDappToolkit] => {
  const {
    dAppDefinitionAddress,
    expectedPcrs,
    networkId,
  } = options || {}

  let isReady: boolean = false
  let verifiedPcrs: Pcrs | undefined

  const ec = new elliptic.ec('ed25519')

  const storageKeyPrefix = `prvn:${dAppDefinitionAddress}:${networkId}`
  const signingKeyStorageKey = `${storageKeyPrefix}:signing_key`
  const pcrsStorageKey = `${storageKeyPrefix}:pcrs`

  let keyPair: elliptic.ec.KeyPair

  const refreshSigningKey = () => {
    if (localStorage.getItem(signingKeyStorageKey)) {
      keyPair = ec.keyFromPrivate(localStorage.getItem(signingKeyStorageKey)!, "hex")
    } else {
      keyPair = ec.genKeyPair()
      localStorage.setItem(signingKeyStorageKey, keyPair.getPrivate("hex"))
    }
  }

  refreshSigningKey()

  if (localStorage.getItem(pcrsStorageKey)) {
    verifiedPcrs = JSON.parse(localStorage.getItem(pcrsStorageKey)!)
    isReady = true
  }

  const radixDappToolkit = RadixDappToolkit({
    ...options,
    onDisconnect: () => {
      localStorage.removeItem(signingKeyStorageKey);
      localStorage.removeItem(pcrsStorageKey);

      // TODO: revoke public key on remote server also

      isReady = false
      refreshSigningKey()
      verifiedPcrs = undefined
    }
  })

  const provenNetworkOrigin = {
    2: 'https://test.weareborderline.com',
  }[networkId]

  const getChallenge: () => Promise<string> = () =>
    fetch(`${provenNetworkOrigin}/create-challenge`)
      .then((res) => res.text())

  radixDappToolkit.walletApi.provideChallengeGenerator(getChallenge)

  const fetchAndVerifyAttestation = async (proofs: WalletData['proofs']) => {
    // get bytes from private key
    const publicKeyInput = new Uint8Array(keyPair.getPublic("array"))

    // generate nonce to verify in response
    const nonceInput = new Uint8Array(32)
    crypto.getRandomValues(nonceInput)

    const body = new FormData()
    body.append("public_key", new Blob([publicKeyInput], { type: 'application/octet-stream' }))
    body.append("nonce", new Blob([nonceInput], { type: 'application/octet-stream' }))
    body.append("signed_challenge", new Blob([JSON.stringify(proofs)], { type: 'application/json' }))

    // send attestation request
    const response = await fetch(`${provenNetworkOrigin}/verify`, {
      method: "POST",
      body
    })
    const data = new Uint8Array(await response.arrayBuffer())

    // decode COSE elements
    const coseElements = await cbor.decodeFirst(data) as Uint8Array[]
    const { cabundle, certificate, nonce, pcrs: rawPcrs, public_key } = await cbor.decodeFirst(coseElements[2]!) as { cabundle: Uint8Array[], certificate: Uint8Array, nonce: Uint8Array, pcrs: Map<number, Uint8Array>, public_key: Uint8Array }
    const leaf = new X509Certificate(certificate)

    // verify public key echoed
    if (!areEqualUint8Array(publicKeyInput, public_key)) {
      throw new Error("public key mismatch")
    }

    // verify nonce or throw error
    if (!areEqualUint8Array(nonceInput, nonce)) {
      throw new Error("nonce mismatch")
    }

    // verify leaf still valid or throw error
    if (leaf.notAfter < new Date()) {
      throw new Error("certificate expired")
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
      throw new Error("chain ca certificate mismatch")
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
        throw new Error(`PCR ${index} mismatch`)
      }
    })

    // save verified PCRs
    localStorage.setItem(pcrsStorageKey, JSON.stringify(pcrs))

    isReady = true
    verifiedPcrs = pcrs
  }

  radixDappToolkit.walletApi.dataRequestControl(async ({ proofs }) => {
    fetchAndVerifyAttestation(proofs)
  })

  return [radixDappToolkit, {
    pcrs: () => verifiedPcrs,
    ready: () => isReady,
  }]
}
