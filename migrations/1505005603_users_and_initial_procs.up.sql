CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS '
BEGIN
  IF row(NEW.*) IS DISTINCT FROM row(OLD.*) THEN
    NEW.dt_modified = now();
    RETURN NEW;
  ELSE
    RETURN OLD;
  END IF;
END;
' language 'plpgsql';


CREATE OR REPLACE FUNCTION set_created_column()
RETURNS TRIGGER AS '
BEGIN
  NEW.dt_created = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
' language 'plpgsql';

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR NOT NULL,
  phone VARCHAR NOT NULL,
  email VARCHAR,
  password VARCHAR NOT NULL,
  confirmation_token VARCHAR,
  confirmation_timestamp TIMESTAMP,
  dt_created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  dt_modified TIMESTAMP
);

CREATE TRIGGER set_dt_created BEFORE INSERT ON users FOR EACH ROW EXECUTE PROCEDURE set_created_column();
CREATE TRIGGER set_dt_modified BEFORE UPDATE ON users FOR EACH ROW EXECUTE PROCEDURE update_modified_column();

CREATE TABLE groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_one UUID REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE,
  user_two UUID REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE,
  dt_created TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  dt_modified TIMESTAMP
);

CREATE TRIGGER set_dt_created BEFORE INSERT ON groups FOR EACH ROW EXECUTE PROCEDURE set_created_column();
CREATE TRIGGER set_dt_modified BEFORE UPDATE ON groups FOR EACH ROW EXECUTE PROCEDURE update_modified_column();
