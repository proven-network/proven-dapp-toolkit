type PcrIndex = 0 | 1 | 2 | 3 | 4 | 8
export type Pcrs = Record<PcrIndex, string>

export type ExpectedPcrs = Partial<Pcrs>

type OptionalProvenDappToolkitOptions = {
  expectedPcrs: ExpectedPcrs
}

type RequiredProvenDappToolkitOptions = {
  dAppDefinitionAddress: string
  networkId: number
}

export type ProvenDappToolkitOptions = Partial<OptionalProvenDappToolkitOptions> &
  RequiredProvenDappToolkitOptions
