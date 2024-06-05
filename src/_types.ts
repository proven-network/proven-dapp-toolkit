import { eddsa } from "elliptic"

type PcrIndex = 0 | 1 | 2 | 3 | 4 | 8
export type Pcrs = Record<PcrIndex, string>

export type ExpectedPcrs = Partial<Pcrs>

export type Session = {
  sessionId: string,
  pcrs: Pcrs,
  signingKey: eddsa.KeyPair,
  verifyingKey: eddsa.KeyPair,
}

export type SerializableSession = {
  sessionId: string,
  pcrs: Pcrs,
  signingKey: string,   // hex
  verifyingKey: string, // hex
}

type OptionalProvenDappToolkitOptions = {
  expectedPcrs: ExpectedPcrs
}

type RequiredProvenDappToolkitOptions = {
  dAppDefinitionAddress: string
  networkId: number
}

export type ProvenDappToolkitOptions = Partial<OptionalProvenDappToolkitOptions> &
  RequiredProvenDappToolkitOptions
