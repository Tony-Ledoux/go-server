-- name: CreateToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
    $1,
    NOW(),
    NOW(),
    $2,
    $3,
    $4
)
RETURNING *;

-- name: RevokeTokenByID :one
UPDATE refresh_tokens
 SET revoked_at = NOW(), updated_at = NOW()
 where token = $1 AND revoked_at IS NULL
RETURNING *;

-- name: GenerateAccessFromRefreshToken :one
SELECT user_id FROM refresh_tokens WHERE token = $1 and revoked_at is NULL and expires_at > NOW();