#!/usr/bin/env python3
"""
Generate mathematically accurate elliptic curve visualizations for mobi-521 documentation.
Outputs SVG files with proper curves and geometric operations.
"""

import numpy as np
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend

# Use a clean style
plt.style.use('seaborn-v0_8-darkgrid')

def elliptic_curve(x, a=-3, b=5):
    """
    Compute y values for elliptic curve y^2 = x^3 + ax + b
    Returns both positive and negative y values
    """
    y_squared = x**3 + a*x + b
    # Only real values where y_squared >= 0
    mask = y_squared >= 0
    y_pos = np.sqrt(y_squared, where=mask)
    y_neg = -y_pos
    return y_pos, y_neg, mask

def plot_elliptic_curve_basic():
    """Generate basic elliptic curve plot"""
    fig, ax = plt.subplots(figsize=(10, 8))

    # Parameters for y^2 = x^3 - 3x + 3 (continuous curve)
    a, b = -3, 3

    # Generate x values - shifted to avoid break at x=0
    x = np.linspace(-2.5, 3, 1000)
    y_pos, y_neg, mask = elliptic_curve(x, a, b)

    # Plot both branches
    ax.plot(x[mask], y_pos[mask], 'b-', linewidth=2.5, label='$y^2 = x^3 - 3x + 3$')
    ax.plot(x[mask], y_neg[mask], 'b-', linewidth=2.5)

    # Styling
    ax.axhline(y=0, color='gray', linestyle='--', linewidth=0.8, alpha=0.5)
    ax.axvline(x=0, color='gray', linestyle='--', linewidth=0.8, alpha=0.5)
    ax.set_title('Elliptic Curve: $y^2 = x^3 + ax + b$', fontsize=16, fontweight='bold')
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=12)
    ax.set_xlim(-2.5, 3)
    ax.set_ylim(-4, 4)

    plt.tight_layout()
    plt.savefig('/home/dd/Documents/mobi-521-github-public/web/assets/elliptic_curve_basic.svg',
                format='svg', bbox_inches='tight', dpi=150)
    print("✓ Generated elliptic_curve_basic.svg")
    plt.close()

def find_line_curve_intersection(x1, y1, x2, y2, a=-3, b=5):
    """
    Find third intersection point of line through (x1,y1) and (x2,y2) with curve
    Uses the fact that for cubic, if we know two roots, we can find the third
    """
    # Line slope
    if abs(x2 - x1) < 1e-10:
        # Vertical line - special case
        return None, None

    m = (y2 - y1) / (x2 - x1)
    c = y1 - m * x1

    # Substitute y = mx + c into y^2 = x^3 + ax + b
    # (mx + c)^2 = x^3 + ax + b
    # x^3 - m^2*x^2 + (a - 2mc)*x + (b - c^2) = 0
    # We know x1 and x2 are roots, so x3 = m^2 - x1 - x2 (Vieta's formulas)

    x3 = m**2 - x1 - x2
    y3 = m * x3 + c

    return x3, y3

def plot_point_addition():
    """Generate point addition geometric visualization"""
    fig, ax = plt.subplots(figsize=(10, 8))

    a, b = -3, 3  # Same as basic curve

    # Generate curve
    x = np.linspace(-2.5, 3, 1000)
    y_pos, y_neg, mask = elliptic_curve(x, a, b)

    # Plot curve
    ax.plot(x[mask], y_pos[mask], 'b-', linewidth=2.5, alpha=0.6)
    ax.plot(x[mask], y_neg[mask], 'b-', linewidth=2.5, alpha=0.6)

    # Choose two points with different y-values for clear visualization
    # P on lower branch, Q on upper branch
    x_p = -1.5
    y_p_sq = x_p**3 + a*x_p + b
    y_p = -np.sqrt(y_p_sq) if y_p_sq >= 0 else None  # Lower branch

    x_q = 2.0
    y_q_sq = x_q**3 + a*x_q + b
    y_q = np.sqrt(y_q_sq) if y_q_sq >= 0 else None  # Upper branch

    if y_p is not None and y_q is not None:
        # Find third intersection point R (on the curve)
        x_r, y_r = find_line_curve_intersection(x_p, y_p, x_q, y_q, a, b)

        if x_r is not None:
            # Calculate line parameters
            m = (y_q - y_p) / (x_q - x_p)
            c = y_p - m * x_p

            # R' is reflection of R across x-axis - this is P + Q
            y_r_prime = -y_r

            # Draw line through P, Q and R (all three on curve)
            x_line = np.linspace(-3, 3, 100)
            y_line = m * x_line + c
            ax.plot(x_line, y_line, 'orange', linestyle='--', linewidth=2.5, alpha=0.8,
                   label='Line through P, Q, R')

            # Draw reflection line (vertical from R to R')
            ax.plot([x_r, x_r], [y_r, y_r_prime], 'gray', linestyle=':', linewidth=2, alpha=0.6,
                   label='Reflection')

            # Plot points with larger markers
            # P, Q, R are all on the curve
            ax.plot(x_p, y_p, 'o', color='#2ECC71', markersize=16, label='P (on curve)', zorder=5,
                   markeredgecolor='darkgreen', markeredgewidth=2)
            ax.plot(x_q, y_q, 'o', color='#3498DB', markersize=16, label='Q (on curve)', zorder=5,
                   markeredgecolor='darkblue', markeredgewidth=2)
            ax.plot(x_r, y_r, 'o', color='#9B59B6', markersize=16, label='R (3rd intersection)', zorder=5,
                   markeredgecolor='purple', markeredgewidth=2)
            # R' is the result P + Q
            ax.plot(x_r, y_r_prime, 'o', color='#E74C3C', markersize=16, label="R' = P + Q", zorder=5,
                   markeredgecolor='darkred', markeredgewidth=2)

            # Labels with better positioning
            ax.text(x_p - 0.4, y_p + 0.5, 'P', fontsize=18, fontweight='bold', color='#2ECC71',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='#2ECC71', linewidth=2))
            ax.text(x_q + 0.3, y_q + 0.5, 'Q', fontsize=18, fontweight='bold', color='#3498DB',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='#3498DB', linewidth=2))
            ax.text(x_r + 0.4, y_r + 0.4, 'R', fontsize=18, fontweight='bold', color='#9B59B6',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='#9B59B6', linewidth=2))
            ax.text(x_r + 0.4, y_r_prime - 0.6, "R' = P + Q", fontsize=16, fontweight='bold', color='#E74C3C',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='#E74C3C', linewidth=2))

    # Styling
    ax.axhline(y=0, color='gray', linestyle='-', linewidth=0.8, alpha=0.5)
    ax.axvline(x=0, color='gray', linestyle='-', linewidth=0.8, alpha=0.5)
    ax.set_title('Point Addition on Elliptic Curve', fontsize=16, fontweight='bold')
    ax.grid(True, alpha=0.3)
    ax.legend(fontsize=10, loc='upper left')
    ax.set_xlim(-2.5, 3)
    ax.set_ylim(-4, 4)

    plt.tight_layout()
    plt.savefig('/home/dd/Documents/mobi-521-github-public/web/assets/point_addition.svg',
                format='svg', bbox_inches='tight', dpi=150)
    print("✓ Generated point_addition.svg")
    plt.close()

def main():
    print("Generating elliptic curve visualizations...")
    plot_elliptic_curve_basic()
    plot_point_addition()
    print("\nAll visualizations generated successfully!")
    print("Files saved in web/assets/")

if __name__ == '__main__':
    main()
