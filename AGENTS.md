# Project guidance

Keep Pinaki SecureVault self-hosted and single-container. Require SQLCipher in every environment that reads application data. Preserve server authorization and the distinction between authentication and vault key handling. Use synthetic data for verification and check the Compose build and HTTPS readiness after deployment changes.
