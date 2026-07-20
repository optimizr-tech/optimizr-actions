# Atomic Environment Writer Design

## Goal
Centralize safe `.env` creation while leaving secret ownership and product-specific keys in each consumer.

## Architecture
A repository-owned version-1 schema maps output keys to environment variable names or non-secret literals. A Python runner validates the schema and paths, renders Compose-safe quoted values, writes inside an explicit allowed root, atomically replaces the destination, and stores sanitized evidence in the workspace.

## Security
Secrets never cross action inputs. Secret defaults and secret literals are rejected. Destination traversal, symlink components, unsafe modes, duplicate keys, NUL values and oversized schemas/values fail closed.

## Testing
Tests cover schema rejection, Compose escaping, required values, atomic mode verification, evidence redaction, allowed-root confinement and symlink targets.
