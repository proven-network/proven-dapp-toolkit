import { type RadixDappToolkitOptions } from "@radixdlt/radix-dapp-toolkit"
import { type SerializableSession } from "../_types"
import * as cbor from "cbor-web"
import { eddsa } from "elliptic"
import { uint8ArrayToHex } from "../helpers/uint8array"

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

  // const callbacks: Map<number, (data: any) => void> = new Map()

  const openWebSocket = async () => {
    if (!localStorage.getItem(sessionStorageKey)) {
      logger?.debug("No active session, cannot open websocket.")
    }

    const session = JSON.parse(localStorage.getItem(sessionStorageKey)!) as SerializableSession
    let connectionOpened = false

    webSocket = new WebSocket(`wss://${host}/ws?session=${session.sessionId}`)
    webSocket.binaryType = "arraybuffer"

    webSocket.onopen = () => {
      connectionOpened = true
      console.log("Connection opened")
    }

    webSocket.onmessage = async (event) => {
      if (typeof event.data === "object") {
        // Assume COSE binary if object
        const data = new Uint8Array(event.data)
        const coseElements = await cbor.decodeFirst(data) as Uint8Array[]

        // FROM COSE SIGN1 SPEC
        //
        // Sig_structure = [
        //   context : "Signature" / "Signature1" / "CounterSignature",
        //   body_protected : empty_or_serialized_map,
        //   ? sign_protected : empty_or_serialized_map,
        //   external_aad : bstr,
        //   payload : bstr
        // ]

        const toBeSigned = await cbor.encodeOne([
          "Signature1",    // context
          coseElements[0], // body_protected
          Buffer.alloc(0), // external_aad
          coseElements[2], // payload
        ])

        const verifyingKey = eddsa.keyFromPublic(session.verifyingKey)
        const verified = verifyingKey.verify(uint8ArrayToHex(toBeSigned), uint8ArrayToHex(coseElements[3]))

        if (!verified) {
          logger?.debug("Signature verification failed")
          return
        }

        const decodedPayload = await cbor.decodeFirst(coseElements[2])

        console.log("Verified and decoded payload", decodedPayload)
      } else if (typeof event.data === "string") {
        logger?.debug("Unexpected string data: ", event.data)
      }
    }

    webSocket.onclose = (event) => {
      console.log("Connection closed", event.code, event.reason, event.wasClean)
      webSocket = undefined
    }

    webSocket.onerror = () => {
      console.log("Connection closed due to error")
    }

    // Wait for connection to open
    while (!connectionOpened) {
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
  }

  const send = async (data: string) => {
    if (!webSocket) {
      await openWebSocket()
    }

    webSocket!.send(data)
  }

  return {
    send,
  }
}
