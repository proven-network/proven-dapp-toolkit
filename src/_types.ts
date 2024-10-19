import { eddsa } from 'elliptic'

export type NetworkEndpoints = {
  createChallenge: string
  rpc: string
  verify: string
  websocket: string
}

type PcrIndex = 0 | 1 | 2 | 3 | 4 | 8
export type Pcrs = Record<PcrIndex, string>

export type ExpectedPcrs = Partial<Pcrs>

export type Session = {
  sessionId: string
  pcrs: Pcrs
  signingKey: eddsa.KeyPair
  verifyingKey: eddsa.KeyPair
}

export type SerializableSession = {
  sessionId: string
  pcrs: Pcrs
  signingKey: string // hex
  verifyingKey: string // hex
}

type OptionalProvenDappToolkitOptions = {
  expectedPcrs: ExpectedPcrs
  localDevelopmentMode: boolean
}

type RequiredProvenDappToolkitOptions = {
  dAppDefinitionAddress: string
  networkId: number
}

export type ProvenDappToolkitOptions =
  Partial<OptionalProvenDappToolkitOptions> & RequiredProvenDappToolkitOptions
