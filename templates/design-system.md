# CVE.ICU Design System

## Overview
This design system ensures consistent styling, typography, and color palette across all CVE.ICU pages. It implements a light blue to light grey color scheme specifically optimized for data visualizations.

## Color Palette

### Base Colors
- **Background Primary**: `#f8f9fa` - Main page background
- **Background Secondary**: `#e9ecef` - Secondary backgrounds
- **Background Content**: `#ffffff` - Card and content backgrounds
- **Text Primary**: `#212529` - Main text color
- **Text Secondary**: `#6c757d` - Secondary text color
- **Text Muted**: `#adb5bd` - Muted text color
- **Border**: `#dee2e6` - Standard borders
- **Border Light**: `#f1f3f4` - Light borders

### Light Blue to Grey Visualization Palette
```css
--viz-color-1: #e3f2fd;  /* Very light blue */
--viz-color-2: #bbdefb;  /* Light blue */
--viz-color-3: #90caf9;  /* Medium light blue */
--viz-color-4: #64b5f6;  /* Medium blue */
--viz-color-5: #42a5f5;  /* Blue */
--viz-color-6: #2196f3;  /* Primary blue */
--viz-color-7: #1e88e5;  /* Darker blue */
--viz-color-8: #1976d2;  /* Dark blue */
--viz-color-9: #9e9e9e;  /* Medium grey */
--viz-color-10: #757575; /* Dark grey */
```

### Chart Colors
- **Primary**: `#2196f3` - Main chart color
- **Secondary**: `#64b5f6` - Secondary chart color
- **Tertiary**: `#90caf9` - Tertiary chart color
- **Quaternary**: `#bbdefb` - Quaternary chart color
- **Accent Colors**: `#81c784`, `#ffb74d`, `#f06292`
- **Grey Variants**: `#e0e0e0`, `#9e9e9e`, `#616161`

## Typography

### Font Family
- **Primary**: `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
- **Base Size**: `16px`

### Font Weights
- **Normal**: `400`
- **Medium**: `500`
- **Semibold**: `600`
- **Bold**: `700`

### Headings
- **H1**: `2.5rem`, `700` weight
- **H2**: `2rem`, `600` weight
- **H3**: `1.5rem`, `600` weight
- **H4**: `1.25rem`, `600` weight

## Spacing System
- **XS**: `0.25rem` (4px)
- **SM**: `0.5rem` (8px)
- **MD**: `1rem` (16px)
- **LG**: `1.5rem` (24px)
- **XL**: `2rem` (32px)
- **XXL**: `3rem` (48px)

## Component Classes

### Cards
- `.card` - Basic card styling
- `.stat-card` - Statistics card with hover effects
- `.viz-card` - Visualization container card
- `.metric-card` - Metric display card with gradient background

### Charts
- `.chart-container` - Chart wrapper with consistent styling
- `.chart-title` - Chart title styling
- `.chart-legend` - Custom legend styling
- `.legend-item` - Individual legend items
- `.legend-color` - Legend color indicators

### Data Tables
- `.data-table` - Styled data tables for charts
- Includes hover effects and sticky headers

### Grids
- `.stats-grid` - Responsive grid for statistics
- `.metric-grid` - Grid for metric cards
- `.year-grid` - Grid for year selection

## JavaScript Utilities

### Color Functions
```javascript
// Get chart colors (default or visualization palette)
getChartColors(count, type = 'chart')

// Generate gradient colors from light blue to grey
getGradientColors(count)

// Add opacity to colors
getColorWithOpacity(color, opacity = 0.8)
```

### Global Color Object
```javascript
window.CVE_COLORS = {
    primary: '#2196f3',
    secondary: '#64b5f6',
    vizColors: [...], // 10-color visualization palette
    chartColors: [...], // 10-color chart palette
    gradients: {...} // Predefined gradients
}
```

## Chart.js Configuration

### Global Defaults
- **Font**: Inter font family across all chart elements
- **Colors**: Light blue to grey palette
- **Tooltips**: Consistent styling with design system
- **Grid**: Light grey grid lines
- **Legend**: Point-style legends with proper spacing

## Responsive Design

### Breakpoints
- **Mobile**: `max-width: 480px`
- **Tablet**: `max-width: 768px`
- **Desktop**: `min-width: 769px`

### Mobile Adaptations
- Reduced font sizes
- Adjusted spacing
- Single-column layouts
- Smaller chart heights
- Simplified legends

## Usage Guidelines

### For New Pages
1. Extend `base.html` template
2. Use CSS variables for colors
3. Apply appropriate component classes
4. Use `getChartColors()` for visualizations
5. Follow responsive patterns

### For Charts
1. Use `CVE_COLORS.chartColors` or `CVE_COLORS.vizColors`
2. Apply consistent Chart.js configuration
3. Use `.chart-container` wrapper
4. Include proper legends and titles

### For Data Display
1. Use `.metric-card` for key metrics
2. Apply `.data-table` for tabular data
3. Use `.viz-card` for visualization containers
4. Follow grid patterns for layouts

## Maintenance
- All colors are defined in CSS variables
- JavaScript utilities are in `base.html`
- Component styles are in `style.css`
- Update this documentation when adding new components
