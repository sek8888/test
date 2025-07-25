CREATE TABLE "users" (
  "id" integer PRIMARY KEY,
  "integration_id" integer UNIQUE,
  "role" enum('patient', 'doctor', 'organization'),
  "name" varchar,
  "surname" varchar,
  "patronymic" varchar,
  "dob" varchar,
  "email" varchar,
  "password" varchar,
  "token" varchar,
  "otp_exp" datetime,
  "otp_token" varchar,
  "forget_exp" datetime,
  "forget_token" varchar,
  "verified" bool,
  "modified_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  "created_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "orders" (
  "id" integer PRIMARY KEY,
  "integration_id" varchar UNIQUE,
  "user_id" integer,
  "doctor_id" integer,
  "number" varchar,
  "blank_count" integer,
  "created_date" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  "modified_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  "created_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE "blanks" (
  "id" integer PRIMARY KEY,
  "order_id" integer,
  "integration_id" varchar UNIQUE,
  "name" varchar,
  "visit_date" datetime,
  "file" varchar,
  "modified_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  "created_at" TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE "orders" ADD CONSTRAINT "orders" FOREIGN KEY ("doctor_id") REFERENCES "users" ("id");

ALTER TABLE "orders" ADD CONSTRAINT "orders" FOREIGN KEY ("user_id") REFERENCES "users" ("id");

ALTER TABLE "blanks" ADD CONSTRAINT "blanks" FOREIGN KEY ("order_id") REFERENCES "orders" ("id");
