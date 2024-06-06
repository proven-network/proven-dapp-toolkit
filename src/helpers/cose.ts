import * as cbor from "cbor-web"
import { eddsa } from "elliptic"
import { uint8ArrayToHex } from "../helpers/uint8array"
import { Result, ok, err } from 'neverthrow'

// Note: This is a tiny implementation of COSE Sign1, using elliptic for signing
// and verifying of EdDSA signatures due to inability to use @auth0/cose due to
// the browser's WebCrypto API not supporting EdDSA.
//
// Notes from cose Signature1 spec:
// Sig_structure = [
//   context : "Signature" / "Signature1" / "CounterSignature",
//   body_protected : empty_or_serialized_map,
//   ? sign_protected : empty_or_serialized_map,
//   external_aad : bstr,
//   payload : bstr
// ]

export const decodeAndVerifyCoseSign1 = async (
  coseSign1: Uint8Array,
  verifyingKey: eddsa.KeyPair,
): Promise<Result<unknown, string>> => {
  const coseElements = await cbor.decodeFirst(coseSign1) as Uint8Array[]

  if (coseElements.length !== 4) {
    return err("Invalid COSE Sign1 structure.")
  }

  const [protectedHeaders,, payload, signature] = coseElements

  const toBeSigned = await cbor.encodeOne([
    "Signature1",     // context
    protectedHeaders, // body_protected
    Buffer.alloc(0),  // external_aad (unused in this case)
    payload,          // payload
  ])

  if (!verifyingKey.verify(uint8ArrayToHex(toBeSigned), uint8ArrayToHex(signature))) {
    return err("COSE Sign1 verification failed.")
  }

  const decodedPayload = await cbor.decodeFirst(payload)
  return ok(decodedPayload)
}

export const CoseSign1Decoder = (verifyingKey: eddsa.KeyPair) => ({
  decodeAndVerify: (coseSign1: Uint8Array) => decodeAndVerifyCoseSign1(coseSign1, verifyingKey)
})

const ed25519Header = Buffer.from([0xa1, 0x01, 0x27]) // -7 = EdDSA

export const encodeSign1 = async (
  payload: unknown,
  signingKey: eddsa.KeyPair,
): Promise<Uint8Array> => {
  const payloadCbor = await cbor.encodeOne(payload)

  const toBeSigned = await cbor.encodeOne([
    "Signature1",    // context
    ed25519Header,   // body_protected
    Buffer.alloc(0), // external_aad (unused in this case)
    payloadCbor,     // payload
  ])

  const signature = Buffer.from(signingKey.sign(toBeSigned).toBytes())
  const coseSign1 = await cbor.encodeOne([ed25519Header, {}, payloadCbor, signature])

  return coseSign1
}

export const CoseSign1Encoder = (signingKey: eddsa.KeyPair) => ({
  encode: (payload: unknown) => encodeSign1(payload, signingKey)
})
