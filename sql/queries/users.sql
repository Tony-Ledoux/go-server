-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: GetUserByName :one
SELECT * FROM users WHERE email = $1 LIMIT 1 ;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1 LIMIT 1 ;

-- name: UpdateUser :one
UPDATE users
SET email = $1,
hashed_password = $2,
updated_at = NOW()
WHERE id = $3 RETURNING *;

-- name: ClearUsers :exec
TRUNCATE TABLE users CASCADE;

-- name: UpgradeUserToRed :one
UPDATE users
SET is_chirpy_red = true, updated_at=NOW()
WHERE id = $1 RETURNING *;