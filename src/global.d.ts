interface Window {
  provenRpcQueue?:
    | RpcQueueItem[]
    | {
        push: (item: RpcQueueItem) => void
      }
}
