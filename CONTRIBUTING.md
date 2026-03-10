# Contributing to TrafficCop

Thank you for your interest in contributing to TrafficCop! We welcome
contributions from everyone. By participating in this project, you agree to
abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting Started

1. Fork the repository and clone your fork
2. Install the latest stable Rust toolchain via [rustup](https://rustup.rs/)
3. See [GETTING_STARTED.md](GETTING_STARTED.md) for build and run instructions

## How to Contribute

### Reporting Bugs

- Search [existing issues](https://github.com/ZerosAndOnesLLC/TrafficCop/issues)
  to avoid duplicates
- Open a new issue with a clear title and description
- Include steps to reproduce, expected behavior, and actual behavior
- Include your Rust version (`rustc --version`) and OS

### Suggesting Features

- Open an issue describing the feature, its motivation, and potential
  implementation approach
- Wait for feedback before starting work

### Submitting Changes

**Always open a GitHub issue before starting work.** This ensures your effort
aligns with the project direction and avoids duplicate work.

1. Open (or find) a GitHub issue for your change
2. Fork the repo and create a branch from `main`
3. Make your changes (see [Coding Standards](#coding-standards) below)
4. Add or update tests as appropriate
5. Ensure all checks pass locally (see [Before Submitting](#before-submitting))
6. Commit using [Conventional Commits](#commit-messages) format
7. Push your branch and open a pull request referencing the issue

## Development Setup

```bash
# Clone your fork
git clone https://github.com/<your-username>/TrafficCop.git
cd TrafficCop

# Build
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench

# Run with a config
cargo run -- -c config/example.yaml
```

## Coding Standards

### Rust Style

- Follow standard Rust conventions and idioms
- Use `async` when possible
- Run `cargo fmt` before committing — CI enforces this
- Run `cargo clippy` and fix all warnings — do not suppress them with
  `#[allow(...)]` unless there is a documented reason
- Remove unused code rather than commenting it out or prefixing with `_`

### Error Handling

- Use `thiserror` for library errors and `anyhow` for application-level errors
- Provide meaningful error messages
- Avoid `.unwrap()` and `.expect()` in library code; they are acceptable in
  tests

### Performance

- TrafficCop is designed for high-throughput, low-latency proxying. Keep
  performance in mind
- Avoid unnecessary allocations on the hot path
- When in doubt, benchmark with `cargo bench`

### Tests

- Add unit tests for new functionality
- Place integration tests in the `tests/` directory
- Tests must pass on the latest stable Rust

## Before Submitting

Run these checks locally before opening a PR. CI runs the same checks and will
block merging on failure.

```bash
# Format
cargo fmt --check

# Lint
cargo clippy -- -D warnings

# Test
cargo test

# Build (ensure no warnings)
cargo build 2>&1 | grep -q "warning" && echo "Fix warnings!" || echo "Clean build"
```

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `ci`,
`chore`

Examples:

```
feat(middleware): add request buffering middleware
fix(tls): resolve ALPN negotiation failure on HTTP/2
docs: update configuration examples for TCP routing
perf(balancer): reduce allocations in round-robin selection
```

## Pull Requests

- Keep PRs focused — one logical change per PR
- Reference the related issue (e.g., `Closes #42`)
- Provide a clear description of what changed and why
- Update documentation if your change affects user-facing behavior
- Be responsive to review feedback

## License

By contributing to TrafficCop, you agree that your contributions will be
licensed under the [MIT License](LICENSE).

## Questions?

Open an issue or reach out at support@zerosandones.us.
