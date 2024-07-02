import {
  DataRequestBuilder,
  RadixNetwork,
} from '@radixdlt/radix-dapp-toolkit'
import { ProvenDappToolkit } from '../src/proven-dapp-toolkit'

document.querySelector('#app').innerHTML = `
  <radix-connect-button />
`

const [rdt, pdt] = ProvenDappToolkit({
  dAppDefinitionAddress: '',
  networkId: RadixNetwork.Stokenet,
  useCache: false,
})

rdt.walletApi.setRequestData(DataRequestBuilder.persona().withProof())

rdt.walletApi.walletData$.subscribe((state) => {
  console.log(state)
})
