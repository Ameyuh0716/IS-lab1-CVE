-- Demo seed data. Passwords are real BCrypt(12) hashes:
--   alice / Alice@Passw0rd   (ROLE_USER)
--   admin / Admin@Passw0rd   (ROLE_ADMIN)
INSERT INTO app_user (username, password_hash, role, created_at) VALUES
  ('alice', '$2a$12$oQPC1fjZYCl0/AdjCSTMj.C0QPfC.xwMYDqZkVAC/f2owgbkWtp8K', 'USER', CURRENT_TIMESTAMP),
  ('admin', '$2a$12$mDL6qQji7Sze9pXn/A1ceeOj2xMeqYswtT5flwOpifiqxCqcOT5fO', 'ADMIN', CURRENT_TIMESTAMP);

INSERT INTO post (title, body, author, created_at) VALUES
  ('Welcome to the secure API', 'This post is served from an in-memory H2 database.', 'alice', CURRENT_TIMESTAMP),
  ('JWT in one sentence', 'A signed token that the server verifies instead of keeping a session.', 'admin', CURRENT_TIMESTAMP);
