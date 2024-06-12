import { type RadixDappToolkitOptions } from "@radixdlt/radix-dapp-toolkit"
import { type SerializableSession } from "../_types"
import { eddsa } from "elliptic"
import { CoseSign1Decoder, CoseSign1Encoder } from "../helpers/cose"

export type WebsocketClient = {
  send: (data: string) => Promise<any>
}

export const WebsocketClient = (
  options: {
    eddsa: eddsa
    host: string
    logger: RadixDappToolkitOptions['logger']
    sessionStorageKey: string
  },
): WebsocketClient => {
  const {
    eddsa,
    host,
    logger,
    sessionStorageKey,
  } = options

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
      logger?.debug("No active session, cannot open websocket.")
      return
    }

    const session = JSON.parse(localStorage.getItem(sessionStorageKey)!) as SerializableSession

    webSocket = new WebSocket(`wss://${host}/ws?session=${session.sessionId}`)
    webSocket.binaryType = "arraybuffer"
    webSocket.onopen = () => { connectionOpened = true }

    const verifyingKey = eddsa.keyFromPublic(session.verifyingKey)
    const coseSign1Decoder = CoseSign1Decoder(verifyingKey)

    webSocket.onmessage = async (event) => {
      if (typeof event.data === "object") {
        // Assume COSE binary if object
        const data = new Uint8Array(event.data)
        const decodedData = await coseSign1Decoder.decodeAndVerify(data)

        if (decodedData.isOk()) {
          logger?.debug("Received data: ", decodedData.value)

          const { seq } = decodedData.value.headers
          if (typeof seq !== "number") {
            logger?.debug("No seq found in headers: ", decodedData.value.headers)
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
          logger?.debug("Failed to decode and verify data: ", decodedData.error)
        }
      } else if (typeof event.data === "string") {
        logger?.debug("Unexpected string data: ", event.data)
      }
    }

    webSocket.onclose = (event) => {
      logger?.debug("Connection closed", event.code, event.reason, event.wasClean)
      closeAndResetWebSocket()
    }

    webSocket.onerror = () => {
      logger?.debug("Connection closed due to error")
      closeAndResetWebSocket()
    }
  }

  const send = async (data: string) => {
    if (!webSocket) {
      await openWebSocket()
    }

    // Wait for connection to open
    while (!connectionOpened) {
      await new Promise((resolve) => setTimeout(resolve, 100))
    }

    // TODO: Don't intantiate all this stuff on every send
    const session = JSON.parse(localStorage.getItem(sessionStorageKey)!) as SerializableSession
    const signingKey = eddsa.keyFromSecret(session.signingKey)
    const coseSign1Encoder = CoseSign1Encoder(signingKey)
    const seq = rpcSeq++
    rpcCallbacks.set(seq, (data) => {
      logger?.debug(`Received response to ${seq}: `, data)
    })

    const encodedData = await coseSign1Encoder.encode(data, { seq })

    webSocket!.send(encodedData)
  }

  return {
    send,
  }
}
