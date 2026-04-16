# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Security

- Filesystem deny rules could be bypassed via path traversal (`../` segments). Request paths are now normalized with `filepath.Clean` before rule matching, and paths containing `..` after normalization are rejected outright. Policy files with `..` in filesystem rule patterns are also rejected at load time.
