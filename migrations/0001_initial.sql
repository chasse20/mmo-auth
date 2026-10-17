-- no-transaction
-- SQLx initial migration: fresh YugabyteDB databases only.
-- Keep this file immutable once applied; add versioned migrations for future changes.
-- SQLx sends a whole file as one PostgreSQL simple-query message. Explicit
-- COMMIT statements close the implicit batch transaction between DDL statements,
-- since YugabyteDB does not enable transactional DDL by default.
-- This baseline is NOT compatible with databases using the older migration history.
-- All application identifiers are PascalCase under the public schema.

CREATE TABLE public."Account"
(
	"AccountId" UUID NOT NULL DEFAULT gen_random_uuid(),
	"CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),

	CONSTRAINT "PK_Account" PRIMARY KEY ("AccountId")
);
COMMIT;
CREATE TABLE public."SteamAccount"
(
	"SteamAccountId" BIGINT NOT NULL,
	"AccountId" UUID NOT NULL,

	CONSTRAINT "PK_SteamAccount" PRIMARY KEY ("SteamAccountId"),
	CONSTRAINT "FK_SteamAccount_Account"
		FOREIGN KEY ("AccountId") REFERENCES public."Account" ("AccountId")
		ON DELETE RESTRICT,
	CONSTRAINT "UQ_SteamAccount_AccountId" UNIQUE ("AccountId"),
	CONSTRAINT "CK_SteamAccount_SteamAccountId" CHECK ("SteamAccountId" > 0)
);
COMMIT;
CREATE TABLE public."SteamLogin"
(
	"SteamLoginId" UUID NOT NULL DEFAULT gen_random_uuid(),
	"StateHash" BYTEA NOT NULL,
	"CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	"ExpiresAt" TIMESTAMPTZ NOT NULL,
	"ConsumedAt" TIMESTAMPTZ NULL,

	CONSTRAINT "PK_SteamLogin" PRIMARY KEY ("SteamLoginId"),
	CONSTRAINT "UQ_SteamLogin_StateHash" UNIQUE ("StateHash"),
	CONSTRAINT "CK_SteamLogin_StateHash" CHECK (octet_length("StateHash") = 32),
	CONSTRAINT "CK_SteamLogin_ExpiresAt" CHECK ("ExpiresAt" > "CreatedAt")
);
COMMIT;
CREATE TABLE public."LoginExchange"
(
	"LoginExchangeId" UUID NOT NULL DEFAULT gen_random_uuid(),
	"AccountId" UUID NOT NULL,
	"CodeHash" BYTEA NOT NULL,
	"CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	"ExpiresAt" TIMESTAMPTZ NOT NULL,
	"ConsumedAt" TIMESTAMPTZ NULL,

	CONSTRAINT "PK_LoginExchange" PRIMARY KEY ("LoginExchangeId"),
	CONSTRAINT "FK_LoginExchange_Account"
		FOREIGN KEY ("AccountId") REFERENCES public."Account" ("AccountId")
		ON DELETE RESTRICT,
	CONSTRAINT "UQ_LoginExchange_CodeHash" UNIQUE ("CodeHash"),
	CONSTRAINT "CK_LoginExchange_CodeHash" CHECK (octet_length("CodeHash") = 32),
	CONSTRAINT "CK_LoginExchange_ExpiresAt" CHECK ("ExpiresAt" > "CreatedAt")
);
COMMIT;
CREATE TABLE public."RefreshToken"
(
	"RefreshTokenId" UUID NOT NULL DEFAULT gen_random_uuid(),
	"AccountId" UUID NOT NULL,
	"FamilyId" UUID NOT NULL,
	"TokenHash" BYTEA NOT NULL,
	"CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	"ExpiresAt" TIMESTAMPTZ NOT NULL,
	"ConsumedAt" TIMESTAMPTZ NULL,
	"RevokedAt" TIMESTAMPTZ NULL,

	CONSTRAINT "PK_RefreshToken" PRIMARY KEY ("RefreshTokenId"),
	CONSTRAINT "FK_RefreshToken_Account"
		FOREIGN KEY ("AccountId") REFERENCES public."Account" ("AccountId")
		ON DELETE RESTRICT,
	CONSTRAINT "UQ_RefreshToken_TokenHash" UNIQUE ("TokenHash"),
	CONSTRAINT "CK_RefreshToken_TokenHash" CHECK (octet_length("TokenHash") = 32),
	CONSTRAINT "CK_RefreshToken_ExpiresAt" CHECK ("ExpiresAt" > "CreatedAt")
);
COMMIT;
CREATE INDEX "IX_SteamLogin_ExpiresAt"
ON public."SteamLogin" ("ExpiresAt");
COMMIT;
CREATE INDEX "IX_LoginExchange_ExpiresAt"
ON public."LoginExchange" ("ExpiresAt");
COMMIT;
CREATE INDEX "IX_RefreshToken_FamilyId"
ON public."RefreshToken" ("FamilyId");
COMMIT;
CREATE INDEX "IX_RefreshToken_ExpiresAt"
ON public."RefreshToken" ("ExpiresAt");
COMMIT;
-- Retain SHA-256 digests of redeemed Steam Web API tickets. Never store tickets.
-- The digest itself is the SteamTicketId primary key (no surrogate UUID).
-- Keep records until the ticket can no longer be valid; this sample does not
-- make assumptions about Steam's ticket validity or automatically prune them.
CREATE TABLE public."SteamTicket"
(
	"SteamTicketId" BYTEA NOT NULL,
	"AccountId" UUID NOT NULL,
	"CreatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),

	CONSTRAINT "PK_SteamTicket" PRIMARY KEY ("SteamTicketId"),
	CONSTRAINT "FK_SteamTicket_Account"
		FOREIGN KEY ("AccountId") REFERENCES public."Account" ("AccountId")
		ON DELETE RESTRICT,
	CONSTRAINT "CK_SteamTicket_SteamTicketId"
		CHECK (octet_length("SteamTicketId") = 32)
);
COMMIT;
