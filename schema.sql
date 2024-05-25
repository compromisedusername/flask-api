DROP TABLE IF EXISTS Message;
DROP TABLE IF EXISTS User;

CREATE TABLE "Message" (
    "Id" INTEGER NOT NULL UNIQUE,
    "Text" TEXT NOT NULL,
    "UserId" INTEGER NOT NULL,
    FOREIGN KEY("UserId") REFERENCES "User"("Id"),
    PRIMARY KEY("Id" AUTOINCREMENT)
);

CREATE TABLE "User" (
	"Id"	INTEGER NOT NULL UNIQUE,
	"Login"	TEXT NOT NULL UNIQUE,
	"Password"	TEXT NOT NULL,
	"Email"	TEXT NOT NULL UNIQUE,
	"Salt"	BLOB NULL,
	PRIMARY KEY("Id" AUTOINCREMENT)
)