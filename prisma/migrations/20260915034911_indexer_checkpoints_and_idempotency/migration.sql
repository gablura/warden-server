-- CreateTable
CREATE TABLE "indexer_checkpoints" (
    "watcher" TEXT NOT NULL,
    "last_block" BIGINT NOT NULL,

    CONSTRAINT "indexer_checkpoints_pkey" PRIMARY KEY ("watcher")
);

-- CreateTable
CREATE TABLE "processed_logs" (
    "tx_hash" TEXT NOT NULL,
    "log_index" INTEGER NOT NULL,
    "watcher" TEXT NOT NULL,
    "processed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "processed_logs_pkey" PRIMARY KEY ("tx_hash","log_index")
);
