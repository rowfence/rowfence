-- The second app's table (prisma/plain/schema.prisma: Prisma's defaults, no schemas), in public, which the app
-- role reads: for the SDK's checks of a model that names no schema (tests/sdk.test.ts)
-- CreateTable
CREATE TABLE "public"."holiday" (
    "code" TEXT NOT NULL,
    "country" TEXT NOT NULL,
    "day" DATE NOT NULL,

    CONSTRAINT "holiday_pkey" PRIMARY KEY ("code")
);

-- CreateIndex
CREATE UNIQUE INDEX "holiday_day_key" ON "public"."holiday"("day");

-- CreateIndex
CREATE UNIQUE INDEX "holiday_country_day_key" ON "public"."holiday"("country", "day");

GRANT SELECT ON "public"."holiday" TO conf_app;
