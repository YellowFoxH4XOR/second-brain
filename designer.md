+++
id = 'designer-ux'
title = 'UI/UX Design Rules (SOTA Edition)'
scope = 'workspace'
target_audience = 'Design & Front-End Teams'
status = 'active'
+++

# UI/UX Design Rules (SOTA Edition)

> These guidelines establish state-of-the-art principles for creating visually stunning, accessible, and performant user interfaces across all products. They apply to designers, frontend engineers, and anyone shaping the user experience.

## 1. Core Design Philosophy
- **User-Centric**: Every pixel exists to solve a user problem. Empathize, test early, iterate often.
- **Accessibility First**: Design to **WCAG 2.1 AA** or higher from day one—color contrast, keyboard navigation, focus order, screen-reader semantics.
- **Consistency & Familiarity**: Leverage our design system to maintain a cohesive look-and-feel. Novelty should never compromise usability.
- **Progressive Enhancement**: Ensure the core experience works on low-spec devices and degraded networks before layering advanced visuals or motion.

## 2. Layout & Spacing
- **8-Point Grid**: All spacing and sizing follow multiples of 4 pts (preferred 8 pt steps for major rhythm).
- **Responsive Breakpoints**: xs (< 600 px), sm (600–959 px), md (960–1279 px), lg (1280–1919 px), xl (≥ 1920 px). Design and test at each breakpoint.
- **Fluid Containers**: Avoid fixed-width layouts. Content should adapt gracefully up to 1440 px with generous white space.

## 3. Color & Contrast
- **Token-Based Palette**: Use the Material palette tokens defined in `src/theme.scss`. Never hard-code hex values in code or design files.
- **Contrast Ratio**: Minimum **4.5:1** for body text, **3:1** for large text and graphical elements.
- **Meaningful Use of Color**: Convey status (success, warning, error) via color **and** iconography/labels to support color-blind users.

## 4. Typography
- **Type Scale**: Follow the established modular scale (1.250 rem base). Heading levels and body styles are predefined in the design system.
- **Line Length**: Optimal reading width is 45–75 characters on desktop.
- **Hierarchy**: Use weight, size, and whitespace—not random color—to signal importance.

## 5. Components & Design System
- **Angular Material as Baseline**: New UI patterns must extend or compose existing Material components before inventing custom ones.
- **Single Source of Truth**: Update the shared Figma library (**/design-system/DesignSystem.fig**) whenever components change.
- **Versioning**: Bump the design system’s semantic version when breaking visual changes occur and document migration steps.

## 6. Interaction & Motion
- **Feedback Matters**: All interactive elements provide immediate visual feedback (hover, focus, pressed states).
- **Motion Guidelines**:
  - Duration: **100–300 ms** for micro-interactions; **400–500 ms** for page-level transitions.
  - Easing: Use `standard` easing curves (`cubic-bezier(0.4, 0, 0.2, 1)`).
  - Purposeful: Motion must communicate state change, not distract.
- **Fitts’s Law**: Ensure interactive hit areas are at least **44×44 px**.

## 7. Accessibility Checklist
- Keyboard trap-free navigation; visible focus indicators.
- Use proper semantic HTML roles (`button`, `nav`, `main`).
- Provide `aria-label`s for non-text controls and alt text for images.
- Support prefers-reduced-motion by disabling decorative animations when requested.

## 8. Performance & Media
- **Optimized Assets**: Use `ngSrc` with `NgOptimizedImage`, modern formats (WebP/AVIF), and lazy loading.
- **Font Loading**: Use `font-display: swap;` and subset fonts to essential glyphs.
- **Skeletons & LQIP**: Implement skeleton screens or low-quality image placeholders for perceived speed.

## 9. Microcopy & Tone
- Clear, concise, and action-oriented language.
- Use **sentence-case** for labels and headings.
- Avoid jargon—speak the user’s language.

---

_Following these rules ensures every interface we ship is inclusive, delightful, and aligned with our brand._ 