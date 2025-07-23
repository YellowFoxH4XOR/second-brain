# Angular 17+ Code Mode Rules (SOTA Edition)

> These SOTA-aligned directives govern all code generation, modification, and refactoring tasks. They are designed to produce exceptionally clean, performant, and secure Angular code that is robust and maintainable. Strict adherence is mandatory.

## 0. The Hippocratic Oath of Coding: First, Do No Harm
- **Primary Directive**: Any change, whether a new feature, a refactor, or a bug fix, must not break existing functionality. This includes direct functionality, related features, unit tests, and end-to-end tests.
- **Contextual Analysis**: Before writing code, thoroughly analyze its integration points. Understand how the component, service, or directive you are modifying is used throughout the application.
- **Non-Regression Mandate**: Your changes must be self-contained or backward compatible. If a breaking change is unavoidable, it must be explicitly flagged for human review with a detailed impact analysis. The goal is zero regressions.

## 1. The Golden Rule: Codebase Consistency
- **Analyze Before You Code**: Before implementing any feature or fix, inspect the surrounding files and directories. Your primary goal is to maintain and enhance the established patterns of the existing codebase.
- **Mirror Existing Patterns**: New code must conform to the architectural and stylistic conventions of the module or feature area. If a feature uses a specific state management pattern (e.g., a simple service store, NgRx), follow it. If files are structured in a certain way, adhere to that structure.
- **One Voice**: The entire codebase should look like it was written by a single, disciplined developer. Consistency overrides personal preference.

## 2. Architecture: Standalone is the Standard
- **Standalone First**: All new components, directives, and pipes **must** be `standalone: true`. `NgModules` are considered legacy and should only be used for interacting with third-party libraries that have not yet adopted standalone APIs.
- **Smart & Presentational Components**: Employ a clear separation between smart/container components (which manage state and data fetching) and presentational/UI components (which receive data via `@Input` and emit events via `@Output`). This promotes reusability and simplifies testing.
- **Dependency Injection with `inject()`**: Prefer the `inject()` function over constructor injection, especially in base classes, router guards/resolvers, and reusable utility functions. This provides greater flexibility and better type inference.

    ```ts
    // ✅ Correct: Using the inject function is flexible and clean.
    export function myReusableAuthGuard(): CanActivateFn {
      return () => {
        const authService = inject(AuthService);
        const router = inject(Router);
        return authService.isLoggedIn() || router.createUrlTree(['/login']);
      };
    }
    ```

## 3. State Management & Reactivity: Signals and RxJS
- **Signals for State**: Use Angular Signals as the primary tool for managing component-level state. They are the most performant and ergonomic way to manage synchronous, reactive values.
    -   `signal()`: For mutable state values.
    -   `computed()`: For values derived from other signals. These are lazily evaluated and memoized.
    -   `effect()`: For side effects that need to react to signal changes, such as logging, analytics, or rendering to a `<canvas>`. Avoid using `effect()` to change other signals; use `computed()` instead. Use with `manualCleanup: true` for effects that need explicit teardown logic.

    ```ts
    // component.ts
    export class UserProfileComponent {
      private userService = inject(UserService);

      firstName = signal('Jane');
      lastName = signal('Doe');
      fullName = computed(() => `${this.firstName()} ${this.lastName()}`);

      constructor() {
        effect(() => {
          // Side effect: Log changes to the user's name
          console.log(`User name changed to: ${this.fullName()}`);
        });
      }
    }
    ```

- **RxJS for Events & Complex Async**: Use RxJS for handling complex asynchronous operations, especially those involving multiple events over time.
    -   **Rule**: Never nest a `.subscribe()` call. Use higher-order mapping operators (`switchMap`, `mergeMap`, `concatMap`, `exhaustMap`).
    -   **Rule**: All subscriptions **must** be managed automatically to prevent memory leaks. The `takeUntilDestroyed()` operator is the standard.

    ```ts
    // component.ts
    import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
    import { toObservable } from '@angular/core/rxjs-interop';

    // ...
    searchQuery = signal('');

    constructor() {
      // Interop between Signals and RxJS
      toObservable(this.searchQuery).pipe(
        takeUntilDestroyed(),
        debounceTime(300),
        distinctUntilChanged(),
        switchMap(query => this.apiService.search(query))
      ).subscribe(results => this.results.set(results));
    }
    ```

## 4. Template & Rendering Logic
- **Built-in Control Flow**: Use the new built-in control flow syntax (`@if`, `@for`, `@switch`). It is more performant and ergonomic than the old structural directives (`*ngIf`, `*ngFor`).
- **Mandatory `track` for `@for`**: Every `@for` block that iterates over a collection of objects **must** include a `track` expression. This is critical for performance, as it allows Angular to uniquely identify items and avoid re-rendering the entire list.

    ```html
    <ul>
      @for (item of items(); track item.id) {
        <li>{{ item.name }}</li>
      } @empty {
        <li>No items found.</li>
      }
    </ul>
    ```

- **Strategic Deferred Loading with `@defer`**: Employ `@defer` blocks to lazily render components that are not immediately visible, are non-critical, or are computationally expensive. Use specific triggers to optimize loading behavior.

    ```html
    @defer (on viewport) {
      <app-heavy-chart [data]="chartData()"/>
    } @placeholder {
      <div class="chart-placeholder">Chart is loading...</div>
    } @loading (minimum 500ms) {
      <mat-progress-spinner mode="indeterminate"/>
    }
    ```
- **View Transitions API**: For routed applications, enable and use the View Transitions API (`withViewTransitions()`) to create smooth, animated transitions between pages, enhancing the user experience.

## 5. Forms
- **Strictly Typed Forms**: All `ReactiveFormsModule` implementations **must** be strictly typed. This prevents a large class of common bugs by ensuring type safety between your form controls and your data model.

    ```ts
    // ✅ Correct: Form is strictly typed.
    userForm = new FormGroup({
      name: new FormControl('', { nonNullable: true, validators: [Validators.required] }),
      email: new FormControl<string | null>(null, [Validators.required, Validators.email]),
    });
    ```

## 6. Testing & Verification
- **Test-Driven Development (TDD)**: Write unit tests *before* or *concurrently with* new code. Every component, service, and utility must have a corresponding `.spec.ts` file.
- **AAA Pattern**: Structure all tests using the Arrange-Act-Assert pattern for clarity.
- **Coverage Mandate**: New or refactored code must achieve a minimum of **90% test coverage**.
- **Component Harnesses for Testing**: All tests for components that use Angular Material or the CDK **must** use Component Test Harnesses. This decouples tests from internal DOM structure, making them more robust and resistant to breaking from style or markup changes.

    ```ts
    // ✅ Correct: Using a harness
    const button = await loader.getHarness(MatButtonHarness.with({text: 'Submit'}));
    expect(await button.isDisabled()).toBe(true);
    ```
- **Testing with `inject`**: Use `TestBed.runInInjectionContext()` to test services or functions that rely on the `inject()` function outside of a standard component constructor.

## 7. Linting, Styling & Naming Conventions
- **Strict Linting**: The codebase must remain 100% compliant with the project's ESLint and Stylelint configurations. Run `eslint --fix` and `stylelint --fix` on all changed files before committing.
- **Scalable SCSS**:
    -   Use a consistent, scalable CSS methodology (e.g., BEM, CUBE CSS) for clear, scoped class names.
    -   Use CSS Custom Properties (variables) for all theme-related values (colors, spacing, fonts).
    -   **Strictly forbid `::ng-deep`** and other view encapsulation-piercing selectors. Use CSS Custom Properties or component inputs to customize child components.
- **File Naming**: `feature.type.ts` (e.g., `invoice-table.component.ts`, `auth-state.service.ts`).
- **Symbol Naming**:
    -   `lowerCamelCase` for methods and properties.
    -   `UpperCamelCase` for classes, interfaces, enums, and types.
    -   **Signals**: `lowerCamelCase` (e.g., `users`, `isLoading`). Do not use a special suffix.
    -   **Observables**: `$` suffix for properties that are Observables (e.g., `users$`).

## 8. Security & Error Handling
- **No Raw HTML Injection**: Never bind to `[innerHTML]` with un-sanitized data. Use Angular's built-in sanitization or, where absolutely necessary, `DomSanitizer` with extreme caution and explicit justification.
- **No Hardcoded Secrets**: Credentials, API keys, or tokens must never be present in source code. Load them from environment files (`environment.ts`) or a secure backend service.
- **Error Response**: When an error is detected (e.g., failed test, linting violation), first attempt to auto-correct it. If not possible, halt execution and **flag the issue for human review**, detailing the error, the file/line number, the rule violated, and the failed correction attempt.

---

> _This is the operational playbook for writing world-class Angular code. Failure to comply will break the build. Repeated violations will require architectural review._
