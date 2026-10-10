-- Folders inside folders, which the app role may read and move; the policy says who may (the next migration)
-- CreateTable
CREATE TABLE "app"."folders" (
    "id" INTEGER NOT NULL,
    "parent_id" INTEGER,
    "owner_id" INTEGER NOT NULL,
    "name" TEXT NOT NULL,

    CONSTRAINT "folders_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "folders_parent_id_idx" ON "app"."folders"("parent_id");

-- CreateIndex
CREATE INDEX "folders_owner_id_idx" ON "app"."folders"("owner_id");


GRANT SELECT, UPDATE ON "app"."folders" TO conf_app;
