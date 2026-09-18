const express = require("express");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const { promisify } = require("util");

const app = express();
const db = new Database("messages.db");

const scryptAsync = promisify(crypto.scrypt);

const PORT = 3000;
const MESSAGE_LIFETIME = 5 * 60 * 1000; // 5 minutes

app.use(express.json());
app.use(express.static("public"));

// For this development version, recreate the table.
// IMPORTANT: This deletes old test messages.
db.exec(`
    DROP TABLE IF EXISTS messages;

    CREATE TABLE messages (
        id TEXT PRIMARY KEY,
        encrypted_message TEXT NOT NULL,
        iv TEXT NOT NULL,
        auth_tag TEXT NOT NULL,
        salt TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        opened_at INTEGER,
        expires_at INTEGER
    );
`);

// --------------------------------------------------
// CREATE PROTECTED MESSAGE
// --------------------------------------------------

app.post("/api/messages", async (req, res) => {
    try {
        const { message, password } = req.body;

        if (!message || !password) {
            return res.status(400).json({
                error: "Message and password are required."
            });
        }

        if (password.length < 4) {
            return res.status(400).json({
                error: "Password must be at least 4 characters."
            });
        }

        // Generate random message ID
        const id = crypto.randomUUID();

        // Generate random encryption values
        const salt = crypto.randomBytes(16);
        const iv = crypto.randomBytes(12);

        // Derive encryption key from password
        const key = await scryptAsync(
            password,
            salt,
            32
        );

        // Encrypt message using AES-256-GCM
        const cipher = crypto.createCipheriv(
            "aes-256-gcm",
            key,
            iv
        );

        let encrypted = cipher.update(
            message,
            "utf8",
            "base64"
        );

        encrypted += cipher.final("base64");

        const authTag = cipher.getAuthTag();

        // Store only a password hash
        const passwordHash = await bcrypt.hash(
            password,
            12
        );

        // Store encrypted message
        db.prepare(`
            INSERT INTO messages
            (
                id,
                encrypted_message,
                iv,
                auth_tag,
                salt,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
            id,
            encrypted,
            iv.toString("base64"),
            authTag.toString("base64"),
            salt.toString("base64"),
            passwordHash,
            Date.now()
        );

        res.json({
            id: id,
            message: "Protected message created."
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Could not create message."
        });
    }
});

// --------------------------------------------------
// UNLOCK PROTECTED MESSAGE
// --------------------------------------------------

app.post("/api/messages/:id/unlock", async (req, res) => {

    try {

        const { id } = req.params;
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({
                error: "Password is required."
            });
        }

        // Find message
        const message = db.prepare(`
            SELECT *
            FROM messages
            WHERE id = ?
        `).get(id);

        if (!message) {
            return res.status(404).json({
                error: "Message not found or already deleted."
            });
        }

        // Check whether message has already expired
        if (
            message.expires_at &&
            Date.now() >= message.expires_at
        ) {

            db.prepare(`
                DELETE FROM messages
                WHERE id = ?
            `).run(id);

            return res.status(410).json({
                error: "This message has expired."
            });
        }

        // Verify password
        const passwordCorrect = await bcrypt.compare(
            password,
            message.password_hash
        );

        if (!passwordCorrect) {
            return res.status(401).json({
                error: "Incorrect password."
            });
        }

        // Start the 5-minute timer only when first opened
        let expiresAt = message.expires_at;

        if (!message.opened_at) {

            const openedAt = Date.now();

            expiresAt = openedAt + MESSAGE_LIFETIME;

            db.prepare(`
                UPDATE messages
                SET opened_at = ?, expires_at = ?
                WHERE id = ?
            `).run(
                openedAt,
                expiresAt,
                id
            );
        }

        // Derive the same encryption key
        const salt = Buffer.from(
            message.salt,
            "base64"
        );

        const key = await scryptAsync(
            password,
            salt,
            32
        );

        const iv = Buffer.from(
            message.iv,
            "base64"
        );

        const authTag = Buffer.from(
            message.auth_tag,
            "base64"
        );

        // Decrypt
        const decipher = crypto.createDecipheriv(
            "aes-256-gcm",
            key,
            iv
        );

        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(
            message.encrypted_message,
            "base64",
            "utf8"
        );

        decrypted += decipher.final("utf8");

        res.json({
            message: decrypted,
            expiresAt: expiresAt
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Could not unlock message."
        });
    }
});

// --------------------------------------------------
// DELETE EXPIRED MESSAGES
// --------------------------------------------------

setInterval(() => {

    try {

        db.prepare(`
            DELETE FROM messages
            WHERE expires_at IS NOT NULL
            AND expires_at <= ?
        `).run(Date.now());

    } catch (error) {

        console.error(
            "Cleanup error:",
            error
        );
    }

}, 10000);

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, () => {

    console.log(
        `Secure Message server running at http://localhost:${PORT}`
    );

});