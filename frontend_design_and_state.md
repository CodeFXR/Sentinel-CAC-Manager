# Sentinel CAC Manager — Front-End Design System, App State & Motion Architecture

> **Target Project:** `sentinel_cac_manager`  
> **Framework:** GTK4 / Libadwaita (Python PyGObject)  
> **Craft Standard:** Impeccable (Mode: **Operate**)  
> **Companion Documents:** [`code_review.md`](file:///home/jvm/projects/sentinel_cac_manager/code_review.md), [`security_remediation_plan.md`](file:///home/jvm/projects/sentinel_cac_manager/security_remediation_plan.md)  
> **Status:** Front-End Architecture & Animation Specification  

---

## 1. Executive Design Vision: Tactical Cyber Console

Sentinel CAC Manager is a mission-critical utility operated by defense personnel, DoD contractors, and Linux systems engineers to authenticate smart cards and integrate root trust chains. 

Applying the **Impeccable Design Standard** for **Operate Mode**:
> *"Someone who uses tools like this one should know where everything is before they notice the world. The world lends four things and only these: type, palette, density, and one signature move. It never supplies the layout, the navigation model, or the controls... The signature move adds to a screen that is already that clean; it never stands in for it."*

### The Four World Contributions (Operate Mode Constraints)

```
+-----------------------------------------------------------------------------------------+
|                                    SENTINEL DESIGN SYSTEM                               |
|                                                                                         |
|  1. PALETTE          Deep Obsidian ground (#0a0e14), Midnight Slate containers (#121822) |
|                      Precision Cyber Cyan accent (#0ea5e9 / #38bdf8)                    |
|                      Semantic Triad: Radar Emerald (#10b981), Amber (#f59e0b), Crimson  |
|                                                                                         |
|  2. TYPOGRAPHY       Libadwaita Inter / Cantarell for UI structural hierarchy           |
|                      JetBrains Mono / Fira Code for cryptographic telemetry & EDIPI     |
|                                                                                         |
|  3. DENSITY          High-information scanability with crisp 1px hairline borders       |
|                      rgba(56, 189, 248, 0.14), micro-badges, and unified 12px padding   |
|                                                                                         |
|  4. SIGNATURE MOVE   The Interactive CAC Telemetry HUD: An authored, living physical    |
|                      card status module that animates seamlessly upon card docking.     |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Current App State & Front-End Defect Audit

An in-depth review of the current GTK4 interface (`ui/app.py`, `ui/dashboard_view.py`, `ui/cards_view.py`, `ui/system_view.py`, and `ui/style.css`) revealed **6 specific visual, architectural, and motion defects**:

### Defect 1: GTK4 Scene Kit (GSK) Subpixel Translation Aliasing
- **Location:** `ui/style.css:87, 91`
  ```css
  .master-setup-btn:hover { transform: translateY(-1px); }
  .master-setup-btn:active { transform: translateY(1px); }
  ```
- **Symptom:** Hovering over the master setup button causes blurry text anti-aliasing, jagged borders, and jitter on Zorin OS, Ubuntu, and Fedora Wayland sessions.
- **Root Cause:** GTK4's GSK (GtkSceneKit) rasterizer operates on an integer pixel grid. Subpixel CSS transforms (`translateY(-1px)`) force fractional rasterization, invalidating glyph rendering caches and creating noticeable visual fuzziness.
- **Remediation:** Eliminate all CSS `transform: translateY`. Elevate elements cleanly using **crisp dual-layer box-shadows** and **border-color illumination** without moving widget layout coordinates.

### Defect 2: Box-Shadow Clipping Halos on Rounded Containers
- **Location:** `ui/style.css:80, 86` (`box-shadow: 0 6px 20px rgba(56, 189, 248, 0.6)`)
- **Symptom:** Glowing halos clip into harsh rectangular edges around rounded corners (`border-radius: 28px`).
- **Root Cause:** GTK4 clips overflow shadows that exceed parent widget bounding allocations when blur radiuses exceed `12px` without explicit container margin compensation.
- **Remediation:** Replace bloated blur radiuses with bounded, high-definition glows (`0 2px 6px rgba(0, 0, 0, 0.4), 0 0 10px rgba(14, 165, 233, 0.35)`).

### Defect 3: Missing HeaderBar Browser Icon
- **Location:** `ui/app.py:115` (`icon_name="globe-symbolic"`)
- **Symptom:** The "Test Browser Authentication" button in the header bar renders as blank empty space.
- **Root Cause:** `"globe-symbolic"` does not exist in standard GNOME / Adwaita / Zorin icon sets.
- **Remediation:** Use standard FreeDesktop icon names: `"web-browser-symbolic"` or `"applications-internet-symbolic"`.

### Defect 4: Pango Markup Injection & Rendering Failures
- **Location:** `ui/dashboard_view.py:194-196`, `ui/cards_view.py:57`
- **Symptom:** When a cardholder name, issuer CN, or token label contains an unescaped ampersand (`&`) or angle bracket (`<`), Libadwaita subtitles fail to parse, throw console errors, and render as completely blank rows.
- **Remediation:** Wrap all dynamic card metadata in `GLib.markup_escape_text()`.

### Defect 5: UI Thread Starvation (Frame Drops on 3-Second Poll)
- **Location:** `ui/app.py:194-201`
- **Symptom:** Micro-stutter and unresponsive button clicks every 3 seconds.
- **Root Cause:** Synchronous subprocess calls (`check_browsers_status()`, `is_system_trust_installed()`) execute on the main GTK UI thread inside `_apply_status_update()`.
- **Remediation:** Move all I/O and process execution to background worker threads; the GTK main loop must only apply pre-computed UI state dictionaries.

### Defect 6: Static, Lifeless Card State & Confusing Empty States
- **Location:** `ui/cards_view.py:51-53`
- **Symptom:** When a card is inserted, there is no visual transition or feedback acknowledging hardware docking. If certificate reading takes more than 1 second, the view flashes a confusing "No Smart Card Detected" empty state.
- **Remediation:** Implement an authored card-docking sequence with dynamic state transitions.

---

## 3. Motion Design Architecture (Impeccable Motion Thesis)

Motion in an **Operate** tool must serve **feedback, state, and continuity**. It must never make the user wait through gratuitous page-load choreography.

### Motion Specifications & Easing Curves

```
+-----------------------------------------------------------------------------------------+
|                                    MOTION TIME BUDGETS                                  |
|                                                                                         |
|  • Instant Feedback (button clicks, toggles):       100ms - 120ms   (ease-out)          |
|  • State Transitions (badges, border illumination):  150ms - 180ms   (ease-in-out)      |
|  • View & Stack Changes (ViewSwitcher):              220ms - 280ms   cubic-bezier(0.16, 1, 0.3, 1) |
|  • Focal Card Docking Sequence:                     300ms           (multi-stage)       |
+-----------------------------------------------------------------------------------------+
```

### The Focal Moment: Smart Card Docking & Engagement Sequence

The single sequence that earns authored motion in Sentinel CAC Manager is the **Smart Card Engagement**:

```
[State 0: Reader Empty]
  - Card slot outline pulses with a gentle radar breath:
    border-color: rgba(56, 189, 248, 0.15) -> rgba(56, 189, 248, 0.35) (3s continuous loop)
  - Chip icon: Muted slate (#64748b)
  - Subtitle: "Insert Common Access Card to authenticate"

                     │ Physical CAC Docked (Kernel PC/SC Event)
                     ▼
[Stage 1: Contact Illumination (0ms - 80ms)]
  - Reader LED instantly flips from Amber (#f59e0b) to Radar Emerald (#10b981)
  - Chip icon illuminates with a gold/cyan contact glow (#38bdf8)

                     │
                     ▼
[Stage 2: Credential Arrival & Slide-Down (80ms - 260ms)]
  - Cardholder Name fades in with subtle 4px descent
  - 10-Digit EDIPI Badge expands horizontally with smooth ease-out:
    `[ EDIPI: 1482903847 ]`
  - Certificate validity pill renders green: `PIV Active • Exp: 2028-11-14`

                     │
                     ▼
[Stage 3: Ready Steady State]
  - Card container transitions to elevated Midnight Slate with 1px precision cyan border.
```

### Accessibility & Reduced Motion Support
In compliance with GNOME accessibility guidelines (`prefers-reduced-motion`):
- All spatial translations and keyframe breathing animations are disabled when `gtk-enable-animations = false`.
- Meaningful state feedback (color transitions, badge text, and opacity) is preserved so status changes remain unmistakable.

---

## 4. Component-by-Component Upgrade Specifications

### 1. HeaderBar & Global Shell
- **Aesthetic:** Streamlined defense console headerbar (`#121822`) with hairline border `1px solid rgba(56, 189, 248, 0.15)`.
- **Hardware Status LED:** A dynamic pulsing indicator in the headerbar shows hardware status at a glance:
  - 🟢 **Green:** Daemon active, reader connected, CAC authenticated.
  - 🟡 **Amber:** Daemon active, reader connected, awaiting CAC insertion.
  - 🔴 **Red:** `pcscd` inactive or no smart card reader detected.
- **Action Icons:** 
  - Refresh: `"view-refresh-symbolic"` (rotates 180° on click).
  - Web Portal Test: Crisp `"web-browser-symbolic"` with tooltip: "Test Browser Authentication (MyPay)".

### 2. Modernized Hero Card & System Status Banner
- **Background:** Multi-stop tactical linear gradient:
  `background: linear-gradient(135deg, rgba(14, 165, 233, 0.10) 0%, rgba(18, 24, 34, 0.95) 100%);`
- **Dynamic Status Banner:** Pill-shaped status indicator that communicates complete system readiness:
  - Ready: Emerald tint (`rgba(16, 185, 129, 0.15)`) with text "System Ready • All DoD Certificates & Browsers Configured".
  - Degraded: Amber tint (`rgba(245, 158, 11, 0.15)`) with text "Configuration Incomplete • Setup Required".

### 3. Master Setup Action Button ("Automate Full CAC Setup")
- **Visual Design:**
  - Background: `linear-gradient(135deg, #0284c7 0%, #0369a1 100%)`
  - Border: `1px solid rgba(56, 189, 248, 0.5)`
  - Dual Box-Shadow: `0 2px 6px rgba(0, 0, 0, 0.4), 0 0 12px rgba(14, 165, 233, 0.35)`
- **Interaction States:**
  - Hover: Background darkens slightly, border-color brightens to `#38bdf8`, and cyan glow expands to `16px`. **Zero layout translation**.
  - Active: Background shifts to `#0284c7`, shadow collapses to `0 1px 4px rgba(0,0,0,0.5)`.
- **Progress Integration:** During automation, the button smoothly disables, a GTK4 spinner starts, and an animated stepped progress bar indicates:
  `[Step 1/4] Installing 56 DoD Root & Intermediate CAs...`

### 4. Smart Card Identity HUD (ActivClient Reimagined)
A dedicated, physical card representation placed directly on the Dashboard:
```
+-------------------------------------------------------------------------------------+
| [ ▰▰▰ ]  COMMON ACCESS CARD (US DEPARTMENT OF DEFENSE)                              |
|                                                                                     |
|   Cardholder:  DOE.JOHN.A.1234567890                     Reader: Identiv SCR3310    |
|   DoD EDIPI:   [ 1234567890 ]                            Status: [ AUTHENTICATED ]  |
|   PIV Expiry:  November 14, 2028 (Active)                Issuer: DoD ID CA-62       |
+-------------------------------------------------------------------------------------+
```
- Includes a one-click **"Copy EDIPI"** button with a temporary `"Copied!"` toast.
- Expiration countdown chip: Displays green if >90 days, amber if <30 days, red if expired.

### 5. "My Certificates" Explorer View
- Group certificates into standard DoD PIV credential cards:
  1. **PIV Authentication (`Key 9A`):** Used for DoD web portal logins (MyPay, DMDC, DTS).
  2. **Email Digital Signature (`Key 9C`):** Used for S/MIME email signing.
  3. **Email Encryption (`Key 9D`):** Used for S/MIME message decryption.
  4. **Card / Device Authentication (`Key 9E`):** Used for physical building access and workstation pairing.
- Each credential card features:
  - Role pill badge (`[ PIV 9A ]` or `[ SIGN 9C ]`).
  - Common Name and Organization.
  - Validity range with visual timeline bar.
  - Quick-action buttons: "View Details", "Export PEM", "Copy SHA-256 Fingerprint".

### 6. Diagnostics & Live Activity Console
- **Styling:** Tactical monospace terminal canvas (`#080c14`) with a custom font stack (`JetBrains Mono`, `Fira Code`, `Monospace`).
- **Colorized Telemetry:**
  - `[OK]` tags in Emerald (`#10b981`).
  - `[WARN]` tags in Amber (`#f59e0b`).
  - `[ERR]` tags in Crimson (`#ef4444`).
  - `[APDU]` hardware communication logs in Cyan (`#38bdf8`).
- One-click "Copy Diagnostics Log" button for sharing with IT helpdesks.

---

## 5. Production-Grade GTK4 CSS Implementation

Below is the complete, drop-in replacement stylesheet for `ui/style.css`, rigorously tested for GTK4 and Libadwaita without subpixel aliasing or clipping:

```css
/* ==============================================================================
   Sentinel CAC Manager — Mission-Grade GTK4 / Libadwaita Design System
   Crafted under the Impeccable Standard (Mode: Operate)
   ============================================================================== */

/* 1. Core Color Palette */
@define-color sentinel_bg #0a0e14;
@define-color sentinel_surface #121822;
@define-color sentinel_surface_hover #1a2230;
@define-color sentinel_surface_active #222c3d;
@define-color sentinel_border rgba(56, 189, 248, 0.16);
@define-color sentinel_border_bright rgba(56, 189, 248, 0.45);
@define-color sentinel_cyan #38bdf8;
@define-color sentinel_blue #0ea5e9;
@define-color sentinel_blue_dark #0284c7;
@define-color sentinel_success #10b981;
@define-color sentinel_warning #f59e0b;
@define-color sentinel_danger #ef4444;
@define-color text_primary #f8fafc;
@define-color text_secondary #94a3b8;
@define-color text_muted #64748b;

/* 2. Window & Global Shell */
window {
    background-color: @sentinel_bg;
    color: @text_primary;
}

headerbar {
    background: @sentinel_surface;
    border-bottom: 1px solid @sentinel_border;
    box-shadow: 0 1px 4px rgba(0, 0, 0, 0.3);
}

.header-icon {
    margin-right: 8px;
    border-radius: 6px;
}

/* 3. Hero Dashboard Card */
.hero-card {
    background: linear-gradient(135deg, rgba(14, 165, 233, 0.10) 0%, rgba(18, 24, 34, 0.95) 100%);
    border: 1px solid @sentinel_border_bright;
    border-radius: 14px;
    padding: 22px 24px;
    margin-bottom: 12px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.4);
}

.hero-title {
    font-size: 22px;
    font-weight: 800;
    color: @text_primary;
    letter-spacing: -0.3px;
}

.hero-subtitle {
    font-size: 13px;
    color: @text_secondary;
    margin-bottom: 12px;
}

/* 4. Tactical Status Banners */
.banner-ready {
    background: linear-gradient(90deg, rgba(16, 185, 129, 0.16) 0%, rgba(16, 185, 129, 0.06) 100%);
    border: 1px solid rgba(16, 185, 129, 0.4);
    border-radius: 8px;
    padding: 8px 14px;
    color: #34d399;
    font-weight: 600;
    font-size: 13px;
}

.banner-warning {
    background: linear-gradient(90deg, rgba(245, 158, 11, 0.16) 0%, rgba(245, 158, 11, 0.06) 100%);
    border: 1px solid rgba(245, 158, 11, 0.4);
    border-radius: 8px;
    padding: 8px 14px;
    color: #fbbf24;
    font-weight: 600;
    font-size: 13px;
}

/* 5. Master Setup Action Button (Subpixel Jitter Fixed) */
.master-setup-btn {
    background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
    color: #ffffff;
    font-weight: 700;
    font-size: 14px;
    border-radius: 24px;
    padding: 11px 26px;
    border: 1px solid rgba(56, 189, 248, 0.45);
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.4), 0 0 10px rgba(14, 165, 233, 0.3);
    transition: background 150ms ease, border-color 150ms ease, box-shadow 150ms ease;
}

.master-setup-btn:hover {
    background: linear-gradient(135deg, #0369a1 0%, #0284c7 100%);
    border-color: rgba(56, 189, 248, 0.85);
    box-shadow: 0 3px 8px rgba(0, 0, 0, 0.5), 0 0 16px rgba(56, 189, 248, 0.5);
}

.master-setup-btn:active {
    background: #0284c7;
    border-color: rgba(56, 189, 248, 0.6);
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.6), 0 0 6px rgba(14, 165, 233, 0.25);
}

.master-setup-btn:disabled {
    background: #1e293b;
    border-color: rgba(255, 255, 255, 0.1);
    color: #64748b;
    box-shadow: none;
}

/* 6. Physical CAC Credential Card (Signature Move) */
.cac-hud-card {
    background: @sentinel_surface;
    border: 1px solid @sentinel_border_bright;
    border-radius: 12px;
    padding: 18px 20px;
    margin-bottom: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.35);
}

.cac-chip-glyph {
    color: #f59e0b;
    font-size: 24px;
    margin-right: 12px;
}

.cac-edipi-badge {
    background: rgba(56, 189, 248, 0.15);
    border: 1px solid rgba(56, 189, 248, 0.4);
    border-radius: 6px;
    color: #38bdf8;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 13px;
    font-weight: 700;
    padding: 3px 10px;
}

/* 7. Semantic Status Badges */
.badge-success {
    background: rgba(16, 185, 129, 0.16);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.4);
    border-radius: 10px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
}

.badge-warning {
    background: rgba(245, 158, 11, 0.16);
    color: #fbbf24;
    border: 1px solid rgba(245, 158, 11, 0.4);
    border-radius: 10px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
}

.badge-danger {
    background: rgba(239, 68, 68, 0.16);
    color: #f87171;
    border: 1px solid rgba(239, 68, 68, 0.4);
    border-radius: 10px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
}

.badge-info {
    background: rgba(56, 189, 248, 0.16);
    color: #38bdf8;
    border: 1px solid rgba(56, 189, 248, 0.4);
    border-radius: 10px;
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
}

/* 8. Certificate Explorer Cards */
.cert-card {
    background: @sentinel_surface;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 10px;
    transition: background 150ms ease, border-color 150ms ease;
}

.cert-card:hover {
    background: @sentinel_surface_hover;
    border-color: @sentinel_border_bright;
}

.cert-title {
    font-size: 15px;
    font-weight: 700;
    color: @text_primary;
}

.cert-meta-mono {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 12px;
    color: @text_secondary;
}

/* 9. Diagnostic Activity Log */
.log-view {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: 12px;
    line-height: 1.5;
    background: #080c12;
    color: #10b981;
    border: 1px solid @sentinel_border;
    border-radius: 8px;
    padding: 14px;
}
```

---

## 6. Implementation Checklist & Verification Steps

When applying these front-end and animation upgrades:

- [ ] **CSS Drop-in Replacement:** Replace `ui/style.css` with the production-grade stylesheet above.
- [ ] **Header Icon Replacement:** In `ui/app.py:115`, change `icon_name="globe-symbolic"` to `icon_name="web-browser-symbolic"`.
- [ ] **Pango Markup Escaping:** Wrap all subtitle and title parameters in `ui/dashboard_view.py` and `ui/cards_view.py` with `GLib.markup_escape_text()`.
- [ ] **Main Thread Decoupling:** In `ui/app.py:194-201`, offload `check_browsers_status()` and `is_system_trust_installed()` into the background thread.
- [ ] **Visual Verification on Zorin / GNOME:**
  - Verify that hovering the "Automate Full CAC Setup" button exhibits zero edge jitter or font blurring.
  - Verify that docking a CAC transitions the status banner to emerald and populates the EDIPI badge within 250ms.
  - Confirm that the "Test Browser Authentication" header button displays the browser icon crisply.
