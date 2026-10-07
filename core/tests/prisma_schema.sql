-- prisma_schema.sql: tables as Prisma makes them from models that say nothing more: in public, named like the
-- model (a capital letter), columns in camelCase, integer keys from a sequence, its own index names, and its
-- table of migrations beside them (tests/prisma.authz, tests/capitals.sh).
DO $r$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN CREATE ROLE app_user NOLOGIN; END IF;
END $r$;
CREATE TABLE "_prisma_migrations" (id varchar(36) PRIMARY KEY, migration_name varchar(255) NOT NULL);
CREATE TABLE "User" (id serial PRIMARY KEY, name text NOT NULL);
CREATE TABLE "Team" (id serial PRIMARY KEY, name text NOT NULL);
CREATE TABLE "TeamMember" (
  "teamId" integer NOT NULL REFERENCES "Team" ON DELETE RESTRICT ON UPDATE CASCADE,
  "userId" integer NOT NULL REFERENCES "User" ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT "TeamMember_pkey" PRIMARY KEY ("teamId", "userId")
);
CREATE TABLE "Folder" (
  id serial PRIMARY KEY,
  name text NOT NULL,
  "ownerId" integer NOT NULL REFERENCES "User" ON DELETE RESTRICT ON UPDATE CASCADE,
  "parentId" integer REFERENCES "Folder" ON DELETE SET NULL ON UPDATE CASCADE
);
CREATE TABLE "Note" (
  id serial PRIMARY KEY,
  title text NOT NULL,
  body text NOT NULL DEFAULT '',
  locked boolean NOT NULL DEFAULT false,
  "folderId" integer NOT NULL REFERENCES "Folder" ON DELETE RESTRICT ON UPDATE CASCADE,
  "authorId" integer NOT NULL REFERENCES "User" ON DELETE RESTRICT ON UPDATE CASCADE
);
CREATE INDEX "TeamMember_userId_idx" ON "TeamMember" ("userId");
CREATE INDEX "Folder_ownerId_idx" ON "Folder" ("ownerId");
CREATE INDEX "Folder_parentId_idx" ON "Folder" ("parentId");
CREATE INDEX "Note_folderId_idx" ON "Note" ("folderId");
CREATE INDEX "Note_authorId_idx" ON "Note" ("authorId");
-- with public, the tables are named one by one: ALL TABLES would hand over Prisma's own
GRANT SELECT ON "User", "Team", "TeamMember", "Folder", "Note" TO app_user;
GRANT INSERT, UPDATE, DELETE ON "Folder", "Note" TO app_user;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_user;

INSERT INTO "User" (id, name) VALUES (1, 'ann'), (2, 'bo'), (3, 'cy'), (4, 'dee');
INSERT INTO "Team" (id, name) VALUES (1, 'eng');
INSERT INTO "TeamMember" VALUES (1, 3);
INSERT INTO "Folder" (id, name, "ownerId", "parentId") VALUES
  (1, 'Ann', 1, NULL), (2, 'Projects', 1, 1), (3, 'Alpha', 1, 2), (4, 'Bo', 2, NULL), (5, 'Dee', 4, NULL);
INSERT INTO "Note" (id, title, body, "folderId", "authorId") VALUES
  (1, 'root note', 'r', 1, 1), (2, 'alpha plan', 'p', 3, 1), (3, 'bo note', 'b', 4, 2), (4, 'dee note', 'd', 5, 4);
SELECT setval(pg_get_serial_sequence('"User"', 'id'), 100), setval(pg_get_serial_sequence('"Team"', 'id'), 100),
       setval(pg_get_serial_sequence('"Folder"', 'id'), 100), setval(pg_get_serial_sequence('"Note"', 'id'), 100);
