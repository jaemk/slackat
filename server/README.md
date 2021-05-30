# server

## Setup

* Install rust
* `cargo install migrant --features postgres`
* The following steps assume you are in the `server/` directory  
* Create a `.env` by copying the `.env.sample`. The migration tool (`migrant`),
  the server application, and the `sqlx`  database library will all automatically
  apply any values listed in your `.env` to the current environment, so you don't
  need to "source" the .env manually.
* Setup a postgres db with the `DB_*` values listed in your env.
* `migrant setup`
* `migrant apply -a`
* Create a slack "app"
* Copy your `SLACK_CLIENT_ID` and `SLACK_SECRET_ID` to your `.env`
* `cargo run`, note that `sqlx` needs to see a `DATABASE_URL` (set in your `.env`)
  environment variable at compile time to validate database queries.
