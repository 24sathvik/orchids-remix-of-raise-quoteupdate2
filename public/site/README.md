# Raise Lab Equipment - Quotation Generator

A clean, responsive single-page web application for generating professional quotations for lab equipment.

## Features

- Secure login with predefined credentials
- Product catalog with search functionality
- Interactive product selection with detailed information
- Customizable pricing, quantities, warranties, and add-ons
- Live bill preview with instant calculations
- Custom charge additions
- Currency conversion between INR and USD
- PDF generation and export
- LocalStorage for saving drafts and past bills
- Fully responsive design

## Technologies Used

- HTML5
- CSS3
- Vanilla JavaScript (ES6+)
- [html2pdf.js](https://github.com/eKoopmans/html2pdf.js) for PDF generation

## How to Run

1. Simply open `index.html` in any modern web browser
2. No build step or server required
3. The application runs completely client-side

## Login Credentials

- **User ID:** `admin`
- **Password:** `RaiseLabs@123`

## File Structure

```
/raise-quote-app/
  index.html          # Main HTML file
  styles.css          # Styling
  app.js              # Application logic
  /images/            # Images folder
    logo.png          # Company logo
    product1.jpg      # Product images (sample)
    ...
```

## Customization

### Changing Login Credentials

Edit the `VALID_USERID` and `VALID_PASSWORD` constants in `app.js`:

```javascript
const VALID_USERID = "your_userid";
const VALID_PASSWORD = "your_password";
```

### Editing Product Catalog

The product catalog is defined as a JavaScript array in `app.js`. You can either:

1. Modify the `PRODUCT_CATALOG` array directly in `app.js`
2. Replace it with a fetch from `/data/products.json` (you would need to create this file)

Each product object has the following structure:

```javascript
{
  "id": "MZR-001",
  "name": "Antibiotic Zone Reader (MZR)",
  "price": 165000,
  "currency": "INR",
  "description": "(100-150 words text...)",
  "features": ["... up to 10-15 items ..."],
  "specifications": ["... up to 6-8 lines ..."],
  "photo": "images/mzr.jpg",
  "addons": [{"code":"CAL-01","name":"Calibration set of 4","price":3500}],
  "warranty_months": 12
}
```

### Adding More Products

The application includes 5 sample products. To add the remaining 15 products:

1. Extend the `PRODUCT_CATALOG` array in `app.js` with additional product objects
2. Ensure each product has:
   - Unique ID
   - Valid price
   - Descriptive text (100-150 words)
   - 10-15 features
   - 6-8 specifications
   - Photo path
   - Add-ons (can be empty array)
   - Warranty period

### Changing Company Information

Modify the `COMPANY_INFO` constant in `app.js`:

```javascript
const COMPANY_INFO = {
    name: "Your Company Name",
    address: "Your Address Line 1<br>Your Address Line 2<br>City, State ZIP",
    email: "contact@yourcompany.com"
};
```

### Updating Logo

Replace `/images/logo.png` with your company logo. For best results:
- Use a transparent PNG
- Recommended size: 200x200 pixels
- Update the logo reference in `app.js` if using a different filename

## Data Storage

All data is stored in the browser's localStorage:
- `rle_next_quote_*`: Tracks the next quote number for each day
- `rle_bills`: Saved finalized bills
- `rle_drafts`: Saved draft quotations

## PDF Generation

Quotes can be exported as PDF files using the "Save as PDF" button. The exported files follow the naming convention:
`RLE-Quote-{quote-number}.pdf`

## Theme Customization

The application uses CSS variables for easy theme customization. Edit the `:root` section in `styles.css` to change colors:

```css
:root {
    --primary-color: #2563eb; /* Primary brand color (blue) */
    --accent-color: #ea580c;  /* Accent color (orange) */
    --light-bg: #f8fafc;      /* Light background */
    --dark-text: #1e293b;     /* Dark text */
    --light-text: #64748b;    /* Light text */
    /* ... other variables */
}
```

## Browser Support

The application works on all modern browsers that support:
- ES6 JavaScript
- localStorage
- Flexbox and CSS Grid
- Fetch API

Tested on:
- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)

## Troubleshooting

### PDF Generation Issues

If PDF generation fails:
1. Ensure you have a stable internet connection (html2pdf.js is loaded from CDN)
2. Check browser console for errors
3. Make sure popups are not blocked

### Login Problems

If login fails:
1. Verify credentials match those in `app.js`
2. Check for typos (case-sensitive)
3. Clear browser cache and try again

### Data Not Saving

If data isn't persisting:
1. Ensure browser storage is enabled
2. Check if in private/incognito mode
3. Verify sufficient disk space is available

## License

This project is proprietary software for Raise Lab Equipment. Unauthorized distribution is prohibited.