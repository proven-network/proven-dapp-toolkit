# Proven dApp Toolkit

## Basic usage

Update initialisation of RadixDappToolkit like so:

```typescript
// Replace this:
import {
  RadixDappToolkit,
  RadixNetwork,
  createLogger,
} from '@radixdlt/radix-dapp-toolkit';

const radixDappToolkit = RadixDappToolkit({
  networkId: RadixNetwork.Stokenet,
  dAppDefinitionAddress: "account_tdx_2_12y7ue9sslrkpywpgqyu3nj8cut0uu5arpr7qyalz7y9j7j5q4ayhv6",
  logger: createLogger(2),
})

// With this:
import ProvenDappToolkit from '@proven-network/proven-dapp-toolkit';
import {
  RadixNetwork,
  createLogger,
} from '@radixdlt/radix-dapp-toolkit';

const [radixDappToolkit, provenDappToolkit] = ProvenDappToolkit({
  networkId: RadixNetwork.Stokenet,
  dAppDefinitionAddress: "account_tdx_2_12y7ue9sslrkpywpgqyu3nj8cut0uu5arpr7qyalz7y9j7j5q4ayhv6",
  logger: createLogger(2),
})
```

Ensure that your data request is asking for proofs for the persona (and optionally for the accounts)

```typescript
radixDappToolkit.walletApi.setRequestData(
  // Persona proof is required - note the .withProof()
  DataRequestBuilder.persona().withProof(),
  // Accounts optional but should be proofed if business logic relies on token balances
  DataRequestBuilder.accounts().atLeast(1).withProof()
)
```

## Work-in-progress

* [x] Session key generation
* [x] Remote attestation of node
* [x] Checking of x509 chain (incl. bundled root certificate match)
* [x] Signing of RPC messages using COSE
* [ ] Calling exported remote functions (blocked pending integration of wit-to-zod transpiler into node WASM build process)
* [ ] Direct storage access calls
* [ ] Subscription to remote events (ledger & proven)
