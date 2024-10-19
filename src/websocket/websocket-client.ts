import { type RadixDappToolkitOptions } from '@radixdlt/radix-dapp-toolkit'
import { type SerializableSession } from '../_types'
import { eddsa } from 'elliptic'
import { CoseSign1Decoder, CoseSign1Encoder } from '../helpers/cose'
import { hexToUint8Array, uint8ArrayToHex } from '../helpers/uint8array'

type WhoAmI = 'WhoAmI'
type WhoAmIResponse = { identity_address: string; account_addresses: string[] }

type Execute = { Execute: [any, string, any[]] }
type ExecuteWithOptions = {
  ExecuteWithOptions: [any, number, number, string, any[]]
}
type ExecuteOutput = string | number | boolean | null | undefined
type ExecuteSuccess = {
  output: ExecuteOutput
  duration: {
    secs: number
    nanos: number
  }
  logs: string[]
}

type RpcCall = WhoAmI | Execute | ExecuteWithOptions

export type WebsocketClient = {
  // Using any for script to work better with raw-loader out of the box
  execute: (
    script: any,
    timeout: number,
    memory: number,
    handler: string,
    args?: any[],
  ) => Promise<ExecuteOutput>
  whoAmI: () => Promise<WhoAmIResponse>
}

export const WebsocketClient = (options: {
  eddsa: eddsa
  logger: RadixDappToolkitOptions['logger']
  sessionStorageKey: string
  websocketEndpoint: string
}): WebsocketClient => {
  const { eddsa, logger, sessionStorageKey, websocketEndpoint } = options

  let webSocket: WebSocket | undefined
  let connectionOpened = false

  let rpcSeq = 0
  let rpcCallbacks: Map<number, (data: any) => void> = new Map()

  const closeAndResetWebSocket = () => {
    if (webSocket && webSocket.readyState === WebSocket.OPEN) {
      webSocket.close()
    }

    webSocket = undefined
    connectionOpened = false

    // no point in keeping rpc state as it is connection-specific
    rpcSeq = 0
    rpcCallbacks = new Map()
  }

  const openWebSocket = async () => {
    if (!localStorage.getItem(sessionStorageKey)) {
      logger?.debug('No active session, cannot open websocket.')
      return
    }

    const session = JSON.parse(
      localStorage.getItem(sessionStorageKey)!,
    ) as SerializableSession
    const externalAad = hexToUint8Array(session.sessionId)

    webSocket = new WebSocket(
      `${websocketEndpoint}?session=${session.sessionId}`,
    )
    webSocket.binaryType = 'arraybuffer'
    webSocket.onopen = () => {
      connectionOpened = true
    }

    const verifyingKey = eddsa.keyFromPublic(session.verifyingKey)
    const coseSign1Decoder = CoseSign1Decoder(verifyingKey, externalAad)

    webSocket.onmessage = async (event) => {
      if (typeof event.data === 'object') {
        // Assume COSE binary if object
        const data = new Uint8Array(event.data)
        const decodedData = await coseSign1Decoder.decodeAndVerify(data)

        if (decodedData.isOk()) {
          const { seq } = decodedData.value.headers
          if (typeof seq !== 'number') {
            logger?.debug(
              'No seq found in headers: ',
              decodedData.value.headers,
            )
            return
          }

          const callback = rpcCallbacks.get(seq)
          if (callback) {
            logger?.debug(`Found callback for seq ${seq}`)
            callback(decodedData.value.payload)
            rpcCallbacks.delete(seq)
          } else {
            logger?.debug(`No callback found for seq ${seq}`)
          }
        } else {
          logger?.debug('Failed to decode and verify data: ', decodedData.error)
        }
      } else if (typeof event.data === 'string') {
        logger?.debug('Unexpected string data: ', event.data)
      }
    }

    webSocket.onclose = (event) => {
      logger?.debug(
        'Connection closed',
        event.code,
        event.reason,
        event.wasClean,
      )
      closeAndResetWebSocket()
    }

    webSocket.onerror = () => {
      logger?.debug('Connection closed due to error')
      closeAndResetWebSocket()
    }
  }

  const send = async (data: RpcCall, callback: (data: any) => void) => {
    if (!webSocket) {
      await openWebSocket()
    }

    // Wait for connection to open
    while (!connectionOpened) {
      await new Promise((resolve) => setTimeout(resolve, 100))
    }

    // TODO: Don't intantiate all this stuff on every send
    const session = JSON.parse(
      localStorage.getItem(sessionStorageKey)!,
    ) as SerializableSession
    const signingKey = eddsa.keyFromSecret(session.signingKey)
    const externalAad = hexToUint8Array(session.sessionId)
    const coseSign1Encoder = CoseSign1Encoder(signingKey, externalAad)
    const seq = rpcSeq++
    rpcCallbacks.set(seq, callback)

    const encodedData = await coseSign1Encoder.encode(data, { seq })

    webSocket!.send(encodedData)
  }

  const processExecuteLogs = (logs: string[]) => {
    logs.forEach((log) => {
      if (log.startsWith('[log]')) {
        logger?.info(log.substring(5))
      } else if (log.startsWith('[error]')) {
        logger?.error(log.substring(7))
      } else if (log.startsWith('[warn]')) {
        logger?.warn(log.substring(6))
      } else if (log.startsWith('[debug]')) {
        logger?.debug(log.substring(7))
      } else if (log.startsWith('[info]')) {
        logger?.info(log.substring(6))
      }
    })
  }

  const execute = (
    script: any,
    timeout: number,
    memory: number,
    handler: string,
    args: any[] = [],
  ): Promise<ExecuteOutput> => {
    const startTime = Date.now()
    return new Promise((resolve, reject) => {
      // SHA256 hash of the script, plus timeout and memory seperated by newlines
      crypto.subtle
        .digest(
          'SHA-256',
          new TextEncoder().encode(`${script}\n${timeout}\n${memory}`),
        )
        .then((rawHash) => uint8ArrayToHex(new Uint8Array(rawHash)))
        .then((optionsHash) => {
          send({ Execute: [optionsHash, handler, args] }, (data) => {
            if (data.ExecuteSuccess) {
              const result = data.ExecuteSuccess as ExecuteSuccess

              const totalDuration = Date.now() - startTime
              logger?.debug(
                `Execution took ${result.duration.secs * 1000 + result.duration.nanos / 1_000_000}ms. Total duration: ${totalDuration}ms`,
              )

              processExecuteLogs(result.logs)

              resolve(result.output)
            } else if (data === 'ExecuteHashUnknown') {
              // Retry with full options (populates the server cache for future requests)
              send(
                {
                  ExecuteWithOptions: [script, timeout, memory, handler, args],
                },
                (data) => {
                  if (data.ExecuteSuccess) {
                    const result = data.ExecuteSuccess as ExecuteSuccess

                    const totalDuration = Date.now() - startTime
                    logger?.debug(
                      `Execution took ${result.duration.secs * 1000 + result.duration.nanos / 1_000_000}ms. Total duration: ${totalDuration}ms`,
                    )

                    processExecuteLogs(result.logs)

                    resolve(result.output)
                  } else if (data.ExecuteFailure) {
                    reject(new Error(data.ExecuteFailure))
                  } else {
                    reject(new Error('Unexpected response from execute'))
                  }
                },
              )
            } else if (data.ExecuteFailure) {
              reject(new Error(data.ExecuteFailure))
            } else {
              reject(new Error('Unexpected response from execute'))
            }
          })
        })
    })
  }

  const whoAmI = (): Promise<WhoAmIResponse> => {
    return new Promise((resolve, reject) => {
      send('WhoAmI', (data) => {
        if (data.WhoAmI) {
          resolve(data.WhoAmI as WhoAmIResponse)
        } else {
          reject(new Error('WhoAmI response is missing'))
        }
      })
    })
  }

  return {
    execute,
    whoAmI,
  }
}
