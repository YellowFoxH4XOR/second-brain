+++
id = 'python-code-protocol-v2'
title = 'Python Code Generation & Refactoring Protocol (SOTA Edition v2)'
scope = 'code-mode-agent'
target_audience = 'Code Mode Agent'
status = 'active'
+++

# Python Code Generation & Refactoring Protocol (SOTA Edition v2)

> This protocol defines the mandatory standards for all Python code generation, refactoring, and analysis. It is designed to produce code that is exceptionally clean, correct, performant, secure, and maintainable, reflecting the highest industry benchmarks. Adherence is non-negotiable.

## The Prime Directive: The Hippocratic Oath of Code

**First, do no harm.** Any change, no matter how small, must not break existing functionality or violate the integrity of the codebase.

1.  **Analyze Context:** Before writing or modifying code, thoroughly analyze the surrounding modules, existing tests, and CI/CD pipeline to understand the full context and impact of your proposed changes.
2.  **Verify Integrity:** After any modification, you **must** run all relevant tests (unit, integration), linters, and static type checkers to confirm that you have introduced no regressions. A change is only complete when the verification pipeline passes.
3.  **Incremental Changes:** Prefer small, atomic commits and changes over large, monolithic ones. This minimizes risk and simplifies debugging.

---

## 1. Codebase Consistency & Architecture

-   **The Golden Rule**: The primary goal is to maintain the established patterns of the existing codebase. The entire codebase must look and feel as if written by a single, disciplined author. **Consistency overrides personal preference.**
-   **Mirror Existing Patterns**: New code **must** conform to the architectural (e.g., layered architecture, microservices, hexagonal) and design patterns (e.g., Repository, Factory, Singleton) already in use within the package.
-   **Understand the 'Why'**: Do not just copy patterns blindly. Understand the reasoning behind the existing design choices and ensure your contributions align with those principles.

## 2. Code Style, Formatting, & Linting

-   **Single Source of Truth**: All project metadata, dependencies, and tool configurations **must** reside in `pyproject.toml`.
-   **Formatting**: All code **must** be formatted with **Black** using the default configuration defined in `pyproject.toml`. No exceptions.
-   **Linting & IQ**: All code **must** pass linting with **Ruff** using the configured rule set. Address or explicitly ignore (`# noqa <RULE_CODE>`) every reported violation with a justification if necessary.
-   **Import Sorting**: Imports **must** be sorted by `isort` (via Ruff). The standard structure is:
    1.  Standard library (`import os`)
    2.  Third-party libraries (`import pandas as pd`)
    3.  First-party/local application libraries (`from my_project.utils import db_connect`)
-   **Naming Conventions**:
    -   `snake_case` for variables, functions, and methods.
    -   `PascalCase` for classes.
    -   `CONSTANT_CASE` for constants.
    -   `_` for intentionally unused variables.
    -   `_` (single leading underscore) as a strong convention for non-public attributes/methods.
-   **Docstrings**: All modules, classes, and public functions/methods **must** have a Google-style docstring. Document the *why* as much as the *what*.

    ```python
    def calculate_risk_score(profile: UserProfile) -> float:
        """Calculates a user's risk score based on their profile activity.

        This function implements the 'Weighted Activity' model to assess
        risk, prioritizing recent failed logins. This is critical for
        early fraud detection.

        Args:
            profile: The user profile object containing activity data.

        Returns:
            A risk score between 0.0 and 1.0, where 1.0 is highest risk.
        """
        # ... function body ...
    ```

## 3. Typing & Static Analysis

-   **Strict Static Analysis**: All code **must** pass static analysis with **Mypy** using a strict configuration.
-   **Zero `Any` Policy**: The `typing.Any` type is forbidden. It defeats the purpose of static typing.
    -   **Alternatives**: Use `object` for "I don't care about the type," or a specific `TypeVar` for generic functions. Use `typing.cast` only as a last resort and with an explanatory comment.
-   **Modern & Precise Types**: Use the most specific and modern types available.
    -   Use the `|` operator for unions (e.g., `str | int`) instead of `typing.Union`.
    -   Use `typing.TypeAlias` to create clear, reusable type definitions (e.g., `UserID = NewType('UserID', int)`).
    -   Use `typing.Literal` for variables that can only hold specific literal values.
    -   Use `typing.Final` to declare constants.
    -   Use `typing.Self` in methods that return an instance of the class (Python 3.11+).

## 4. Idiomatic & Performant Python

-   **Comprehensions & Generators**: Use list/dict/set comprehensions for concise collection creation. For large datasets, use generator expressions (`(x for x in data)`) to minimize memory footprint.
-   **Context Managers (`with`)**: Always use the `with` statement for managing resources like files, database connections, and locks to ensure automatic cleanup.
-   **Path Handling**: **Must** use the `pathlib` module for all filesystem path manipulations. It is object-oriented and platform-agnostic, replacing `os.path`.
-   **Enumerations over Magic Strings**: **Must** use the `enum` module to define sets of related constants. This prevents typos and improves code clarity.
-   **Structural Pattern Matching**: Use the `match...case` statement (Python 3.10+) for complex conditional logic that is clearer than a long `if/elif/else` chain.
-   **Exception Handling**: Be specific. Catch concrete exceptions (`except KeyError:`) instead of generic ones (`except Exception:`).

## 5. Testing & Validation

-   **Arrange, Act, Assert (AAA)**: Structure all tests clearly using the AAA pattern.
-   **Fixtures over Setup**: **Must** use `pytest` fixtures for test setup and teardown. They are modular, reusable, and explicit.
-   **Parametrization**: Heavily use `@pytest.mark.parametrize` to test a wide range of inputs and edge cases with minimal code duplication.
-   **Targeted Mocking**: Use `unittest.mock` (via `pytest-mock`) to mock external collaborators, not the system under test itself. Mocks should be as specific as possible.
-   **Test Coverage**: Aim for high test coverage (e.g., >90%) and use tools like `pytest-cov` to measure it. Every new feature or bug fix must be accompanied by corresponding tests.

## 6. Security Imperatives

-   **Never Trust Input**: Treat all data from external sources (users, APIs, files) as untrusted. Validate, sanitize, and type-check it at the application boundary using libraries like Pydantic.
-   **No Remote Code Execution**:
    -   Never use `eval()`, `exec()`.
    -   Never deserialize data from an untrusted source with `pickle` or `yaml.unsafe_load()`. Use safer serialization formats like JSON.
-   **Command Injection Prevention**: When using `subprocess`, always use `shell=False` (the default) and pass arguments as a sequence. If `shell=True` is unavoidable, sanitize all inputs with `shlex.quote()`.
-   **Dependency Security**: Regularly scan for vulnerable dependencies using tools like `pip-audit` or integrated platform features (e.g., GitHub Dependabot).
-   **`assert` is for Debugging**: Do not use `assert` for data validation or security checks that must run in production. `assert` statements are removed when Python is run with the `-O` (optimize) flag. Use explicit checks and raise exceptions.

## 7. FastAPI Best Practices

-   **Async Everywhere for I/O**: All path operation functions that perform any form of I/O (database, network, disk) **must** be `async def`.
-   **Modern Dependency Injection**: **Must** use `typing.Annotated` with FastAPI's `Depends` for all dependency injection. This is the modern, explicit, and type-checker-friendly approach.

    ```python
    from typing import Annotated
    from fastapi import Depends, FastAPI
    from sqlalchemy.orm import Session
    from .dependencies import get_db_session

    app = FastAPI()

    @app.get("/items/")
    async def read_items(db: Annotated[Session, Depends(get_db_session)]):
        # Use the injected database session
        return db.query(Item).all()
    ```

-   **Structured Routing**: **Must** use `APIRouter` to organize path operations into separate modules by domain/feature.
-   **Background Tasks**: For non-blocking post-response operations (e.g., sending emails), **must** use `BackgroundTasks`.
-   **Specific Status Codes & Responses**: Use precise HTTP status codes (`status.HTTP_201_CREATED`, `status.HTTP_204_NO_CONTENT`).
-   **Separate I/O Models**: Use distinct Pydantic models for input (e.g., `ItemCreate`) and output (e.g., `ItemRead`) to prevent mass assignment vulnerabilities and avoid accidentally leaking internal data.

## 8. Dependency Management

-   **Reproducible Environments**: All projects **must** use a lock file to pin the exact versions of all direct and transitive dependencies. This is typically `poetry.lock`, `pdm.lock`, or a `requirements.txt` generated by a tool like `pip-tools`.
-   **Modern Tooling**: **Must** use a modern dependency management tool like **Poetry** or **PDM**. These tools manage virtual environments, dependencies, and `pyproject.toml` cohesively.

## 9. Auto-Correction & Error Handling Protocol

-   Upon detecting a linting or formatting error, first attempt to auto-correct it using the configured tools (`ruff --fix`, `black .`).
-   If auto-correction fails or a type error is detected, halt implementation.
-   **Flag for Human Review**: Report the tool's exact output, the file and line number, and the code snippet in question. Explain why the automated fix likely failed and await human guidance. **Do not proceed with broken code.**
