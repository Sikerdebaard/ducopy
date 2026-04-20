# GitHub Copilot Review Instructions

## Review Philosophy

Provide **comprehensive, thorough reviews in a single pass**. Do not provide iterative feedback with just 1-2 points at a time. Analyze the entire PR deeply and surface ALL concerns, suggestions, and improvements upfront.

## Review Scope

When reviewing this codebase:

1. **Be Exhaustive, Not Iterative**: Identify ALL issues in one comprehensive review:
   - Code quality issues
   - Security vulnerabilities
   - Performance concerns
   - Type safety issues
   - Error handling gaps
   - Test coverage gaps
   - Documentation inconsistencies
   - API design issues
   - Backwards compatibility breaks
   - Edge cases not handled

2. **Context-Aware Analysis**: This is a Python library for DucoBox ventilation units with:
   - Dual board support (modern Connectivity Board with HTTPS + legacy Communication/Print Board with HTTP)
   - Pydantic v1 and v2 compatibility requirement
   - CLI via Typer
   - Type hints required (ruff with ANN checks)
   - Test coverage via pytest

3. **Priority Areas**:
   - **Type Safety**: All functions must have proper type hints, including return types
   - **Error Handling**: Proper exception handling with meaningful error messages
   - **Backwards Compatibility**: Changes must not break existing API contracts
   - **Test Coverage**: New code should have corresponding tests
   - **Documentation**: Docstrings, README examples, and type hints must be accurate
   - **Board Detection Logic**: Critical that both board types work correctly
   - **Caching Strategies**: Performance-critical, verify TTLs and invalidation
   - **API Consistency**: Both board types should have similar interfaces where possible

4. **Code Quality Standards**:
   - Follow existing patterns in the codebase
   - No redundant comments on self-documenting code
   - Prefer explicit over implicit
   - Use modern Python 3.10+ syntax (union types with `|`, match statements if appropriate)
   - Handle edge cases (None, empty lists, network failures, SSL errors)

5. **Testing Requirements**:
   - Unit tests with mocked requests
   - Test both board types where applicable
   - Test error conditions
   - Verify type hints with mypy if possible

## What to Flag

- **Type safety violations**: Missing type hints, incorrect types, use of `Any` without justification
- **Error handling gaps**: Unhandled exceptions, poor error messages, missing validation
- **Test gaps**: Untested code paths, missing edge case tests
- **Documentation drift**: Code that doesn't match docstrings or README examples
- **Performance issues**: Unnecessary network calls, inefficient caching, blocking operations
- **Security issues**: SSL/TLS handling, input validation, credential storage
- **Breaking changes**: API changes that break backwards compatibility without justification
- **Code duplication**: Repeated logic that should be extracted to helpers
- **Inconsistency**: Different patterns for the same problem across the codebase

## Review Output Format

Structure reviews as:

1. **Critical Issues** (blocking): Security, crashes, data loss, breaking changes
2. **Major Issues** (should fix): Type safety, error handling, test gaps, performance
3. **Minor Issues** (nice to have): Code style, optimization opportunities, documentation improvements
4. **Suggestions**: Optional enhancements, refactoring ideas, future considerations

Provide ALL issues in each category upfront, not incrementally.

## What NOT to Flag

- Code style issues already handled by ruff/black (formatting, line length, etc.)
- Personal preference items that don't impact functionality
- Overly pedantic nitpicks that don't add value
- Suggestions already explicitly handled elsewhere in the codebase

## Goal

**One comprehensive review that identifies everything worth addressing**, allowing the developer to make informed decisions about what to fix rather than discovering issues incrementally through multiple review iterations.
