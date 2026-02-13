// =========================
// app.js — Full (fixed amount spacing + layout tweaks)
// =========================

// Hardcoded credentials
const VALID_USERID = "admin";
const VALID_PASSWORD = "RaiseLabs@123";

// Company information
const COMPANY_INFO = {
    name: "Raise Lab Equipment",
    address: "Plot No. 123, Industrial Area,\nHyderabad, Telangana 500042\nPhone: +91 91777 70365",
    email: "info@raiselabequipment.com"
};

// Helper: get base64 data URL by key or return provided dataURL
function getBase64(keyOrUrl) {
    if (!keyOrUrl) return null;
    if (typeof keyOrUrl === 'string' && keyOrUrl.startsWith('data:image')) return keyOrUrl;
    if (window.BASE64_IMAGES && BASE64_IMAGES[keyOrUrl]) return BASE64_IMAGES[keyOrUrl];
    const last = (typeof keyOrUrl === 'string') ? keyOrUrl.split('/').pop() : null;
    if (last && window.BASE64_IMAGES && BASE64_IMAGES[last]) return BASE64_IMAGES[last];
    return null;
}

// PRODUCT CATALOG (photos point to keys in BASE64_IMAGES)
const PRODUCT_CATALOG = [
    {
        id: "MZR",
        name: "Antibiotic Zone Reader (MZR)",
        price: 165000,
        currency: "INR",
       description: "The antibiotic zone reader provides an immediate and accurate method for determining the strength of antibiotic materials by measuring the diameter of an inhibition zone in a Petri-dish. Antibiotic Zone Reader (Model : mZR) measures the diameter of the inhibition zone from 0.01 mm to 35.00 mm with an accuracy better than 0.05 mm.",

        features: [
            "User Friendly Operational Procedure",
            "Economical & Cost Effective",
            "Fast, Simple & Easy to Operate",
            "Measurement Range 0.01 mm to 35.00 mm",
            "0.01 Resolution",
            "Microprocessor based reading of Measurement",
            "Easy to Calibrate, Validate by Certified Coins (9 mm, 18 mm, 27 mm, 35 mm)",
            "Direct Measurement reading on LCD Display",
            "Magnification of Zone for better Accuracy in Measurement",
            "In-Built Thermal Printer available for taking hard copy of Test Report",
            "RS-232 Port for Connecting with PC or Serial Printer"
  ],

        specifications: [
            "Zone Diameter Range: 0.01 mm to 35.00 mm",
            "Accuracy: Better than 0.05 mm",
            "Resolution: 0.01 mm",
            "Display: LCD Display",
            "Illumination Lamp: LED (230V AC)",
            "Power: 230V AC / 50Hz / 1 Amp (Or) 110V AC / 60Hz / 1 Amp (on request)"
        ],
        photo: "./Images/antibiotic-zone-reader.png",//NOT AVI
        addons: [
            { code: "CAL-01", name: "Calibration set of 4", price: 3500 },
            { code: "PRN-01", name: "Additional thermal paper pack", price: 800 }
        ],
        warranty_months: 12
    },
    {
        id: "RPHT-1P",
        name: "Manual Hardness Tester RPHT-1P",
        price: 225000,
        currency: "INR",
        description: "Tablet hardness testers determine the force needed to break a tablet, ensuring consistent quality and performance by measuring the tablet's resistance. Our Portable Digital Hardness Tester (Model: RPHT-01P) measures the hardness of tablets size up to 40 mm in diameter.",

        features: [
            "Cost-Effective, Reliable and Portable",
            "4 Digit seven segments LED Display with Portable four keys membrane keypad",
            "Very Compact, Simple & Easy to operate with 4 Keys",
            "Selectable Units of measurement: N, Kp (Kgf), SC, Lb",
            "Stainless Steel (SS304) Body and test platform & Jaws are of SS316",
            "Microprocessor based Measurement of Tablet Hardness",
            "Statistical Data - Maximum, Minimum and Mean",
            "Test Report consists of results with statistical data",
            "Easy to calibrate with an Optional Calibration Kit consisting of 5Kg Certified Weight",
            "Battery Operated (Using a 9V Rechargeable Battery) as well as AC Power Adapter"
        ],

        specifications: [
            "Display: 4 Digit Seven Segment LED for Value",
            "Hardness Range: 3 N to 500 N",
            "Accuracy: 0.1 N",
            "Resolution: 0.1 N / 0.01 Kp",
            "Tablet Size: Up to 40 mm tablet",
            "Indicators: Visual Indicator with LED for unit of measurement",
            "Power: 9V Rechargeable Battery, 5V AC Power Adapter (100-230V AC, 50Hz, 500 mAmp)"
        ],
        photo: "./Images/TABLET HARDNESS TESTER RHT-3B.png",
        addons: [
            { code: "FLR-01", name: "Fluorescence detection module", price: 45000 },
            { code: "PIP-01", name: "8-channel pipettor", price: 12000 }
        ],
        warranty_months: 24
    },
    {
        id: "HTDS-1P",
        name: "Tablet Hardness Tester (HTDS-1P)",
        price: 89000,
        currency: "INR",
        description: "Tablet hardness testers determine the force needed to break a tablet, ensuring consistent quality and performance by measuring the tablet's resistance. Our Tablet Hardness Tester (Model: HTDS-1P) measures the hardness of tablets size up to 40 mm in diameter.",

        features: [
            "Compact design: Space-saving with an advanced microprocessor design",
            "Accurate hardness measurement providing precise measurements of tablet hardness",
            "User-friendly operation with menu-driven interface and PC-compatible keyboard",
            "20x4 character LCD display",
            "Units of hardness measurement include Newton (N), Kilopond (Kp), Strong cobb (Sc) & user defined (Ud)",
            "Versatile sample accommodation allowing testing of tablets of any shape up to 40 mm in diameter",
            "Recipe management capable of creating, storing, and recalling up to 99 different product recipes",
            "Adjustable sample size with flexibility up to 100 valid samples per test",
            "Simple and easy calibration and verification using certified 5 Kg weight",
            "Reporting capability with generation of various reports for enhanced data analysis",
            "Printer compatibility supporting dot matrix – Epson compatible printer",
            "IQ/OQ documentation included for quality assurance and regulatory compliance"
  ],

        specifications: [
            "Display: 20x4 LCD display",
            "Operation: Front operation panel & PC compatible keyboard",
            "Parameter: Hardness measurement range 3 N to 500 N",
            "Interfaces: Parallel printer interface (Dot Matrix LX310), PC interface using HyperTerminal through RS-232 port",
            "Power: 230V AC / 50Hz / 3 Amps (Or) 110V AC / 60Hz / 3 Amps (on request)"
  ],
        photo: "./Images/TABLET HARDNESS TESTER RHT-3B.png",
        addons: [
            { code: "LMS-01", name: "LIMS integration package", price: 15000 },
            { code: "MOB-01", name: "Mobile stand with tablet mount", price: 5000 }
        ],
        warranty_months: 12
    },
    {
        id: "HTDS-3P",
        name: "Tablet Hardness Tester (HTDS-3P)",
        price: 145000,
        currency: "INR",
        description: "Tablet hardness testers determine the force needed to break a tablet, ensuring consistent quality and performance by measuring the tablet's resistance. Our Tablet Hardness Tester (Model: HTDS-3P) measures the thickness, diameter, and hardness of tablets size up to 45 mm in diameter.",

        features: [
            "Accurately measures tablet thickness and diameter (accuracy 0.02 mm) and hardness",
            "Accuracy in grams of tablets",
            "User-friendly interface with PC-compatible keyboard and 20x4 character LCD display",
            "Display of hardness measurement units: Newton (N), Kilopond (Kp), Strong Cobb (Sc) & user defined",
            "Precise positioning of samples accommodates any tablet up to 45 mm in diameter",
            "100 different product recipes can be created, stored, and recalled",
            "Selectable sample size up to 100 valid samples per test",
            "Simple and easy calibration using certified 10 mm gauge block and easy hardness parameter calibration",
            "Parallel printer port & RS-232 interface for taking hard copies of test reports",
            "IQ/OQ documents included"
         ],

        specifications: [
            "Display: 20x4 LCD display with backlight",
            "Operation: Front operating panel & PC compatible keyboard",
            "Parameters: Thickness 0.1 mm to 20 mm, Diameter 0.1 mm to 45 mm, Hardness 3 N to 500 N",
            "Interfaces: PC-compatible keyboard & parallel printer interface (Epson Dot Matrix LX310)",
            "Power: 230V AC / 50Hz / 3 Amps (Or) 110V AC / 60Hz / 3 Amps (optional)"
        ],
        photo: "./Images/TABLET HARDNESS TESTER RHT-3B.png",
        addons: [
            { code: "BAR-01", name: "Barcode scanner module", price: 8000 },
            { code: "TMP-01", name: "Temperature control module", price: 22000 }
        ],
        warranty_months: 24
    },
    {
        id: "RABT-3",
        name: "Ampoule Breakpoint Tester (RABT-3)",
        price: 45000,
        currency: "INR",
        description: "Ampoule Breakpoint Tester is designed to measure the breaking force required to snap open glass ampoules, ensuring consistent quality and compliance with pharmaceutical standards. The tester provides accurate and repeatable results for routine quality control testing.",

        features: [
            "Microprocessor based instrument for accurate ampoule breakpoint measurement",
            "Digital display for direct reading of breaking force",
            "User-friendly operation with simple and easy controls",
            "Suitable for testing different sizes of glass ampoules",
            "Statistical analysis including minimum, maximum, and average values",
            "Calibration facility using certified standard weights",
            "Robust and compact construction for laboratory use",
            "Provision for connecting printer for test report generation"
  ],

        specifications: [
            "Measurement Range: As per ampoule size",
            "Display: Digital display",
            "Operation Mode: Manual",
            "Calibration: Certified standard weights",
            "Application: Glass ampoule breakpoint testing",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
  ],
        photo: "./Images/AMPOULE BREAKPOINT TESTER RABT-3.png",
        addons: [
            { code: "GEL-01", name: "Horizontal gel tank system", price: 18000 },
            { code: "DOC-01", name: "UV transilluminator", price: 25000 }
        ],
        warranty_months: 12
    },
     {
        id: "TFT",
        name:"Tablet Friability Tester",
        price: 165000,
        currency: "INR",
        description: "Tablet Friability Tester is designed to determine the friability of tablets, ensuring their ability to withstand mechanical stress during handling, packaging, and transportation. It provides reliable and reproducible results for routine quality control testing in pharmaceutical laboratories.",

        features: [
            "Microprocessor based instrument for accurate friability testing",
            "User-friendly operation with simple control panel",
            "Programmable test parameters such as time and number of rotations",
            "Transparent acrylic drum for clear visibility of tablets during test",
            "Automatic stop after completion of test cycle",
            "Robust and compact design suitable for laboratory environments",
            "Compliance with pharmacopoeial standards"
  ],

        specifications: [
            "Drum: Acrylic drum",
            "Speed: 25 rpm",
            "Test Duration: Programmable",
            "Display: Digital display",
            "Operation: Automatic",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
  ],
        photo: "./Images/TABLET FRIABILITY TESTER RFT-2P.png",
        addons: [
            { code: "CAL-01", name: "Calibration set of 4", price: 3500 },
            { code: "PRN-01", name: "Additional thermal paper pack", price: 800 }
        ],
        warranty_months: 12
    },
    {
        id: "TDT",
        name: "Tablet Disintegration Tester",
        price: 225000,
        currency: "INR",
         description: "Tablet Disintegration Tester is designed to determine whether tablets or capsules disintegrate within the specified time under prescribed conditions. It is widely used in pharmaceutical quality control laboratories to ensure compliance with pharmacopoeial standards.",

        features: [
            "Microprocessor based instrument for reliable disintegration testing",
            "User-friendly operation with simple control panel",
            "Automatic lifting and lowering of basket assembly",
            "Digital timer for accurate test duration",
            "Transparent water bath for clear observation during test",
            "Available in manual and automatic models",
            "Designed to comply with USP, IP and BP standards"
  ],

        specifications: [
            "Stations: 6 basket assembly",
            "Display: Digital display",
            "Timer: Digital programmable timer",
            "Temperature Range: Ambient to 45°C",
            "Operation: Manual / Automatic",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
  ],
        photo: "./Images/AUTOMATIC TABLET DISINTEGRATION TESTER ADT-1D.png",
        addons: [
            { code: "FLR-01", name: "Fluorescence detection module", price: 45000 },
            { code: "PIP-01", name: "8-channel pipettor", price: 12000 }
        ],
        warranty_months: 24
    },
    {
        id: "LTA",
        name: "Leak Test Apparatus",
        price: 89000,
        currency: "INR",
        description: "Leak Test Apparatus is designed to detect leakage in strip packs, blister packs, bottles, and containers by creating a vacuum environment. It ensures packaging integrity and helps maintain product quality in pharmaceutical and packaging laboratories.",

        features: [
            "Compact and rugged construction suitable for laboratory use",
            "Transparent vacuum chamber for clear visibility during testing",
            "Vacuum gauge for accurate pressure monitoring",
            "User-friendly operation with simple controls",
            "Suitable for testing strip packs, blister packs, bottles, and containers",
            "Ensures packaging integrity and quality assurance",
            "Low maintenance and easy to operate"
  ],

        specifications: [
            "Chamber: Transparent acrylic vacuum chamber",
            "Vacuum Gauge: Analog gauge",
            "Operation: Manual",
            "Application: Leak testing of pharmaceutical packaging",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
  ],
        photo: "./Images/LEAK TEST APPARATUS RLT-2B.png",
        addons: [
            { code: "LMS-01", name: "LIMS integration package", price: 15000 },
            { code: "MOB-01", name: "Mobile stand with tablet mount", price: 5000 }
        ],
        warranty_months: 12
    },
    {
        id: "LTAD",
        name: "Leak Test Apparatus – Digital",
        price: 145000,
        currency: "INR",
        description: "Leak Test Apparatus – Digital Model is designed to detect leaks in strip packs, blister packs, bottles, and containers by creating a controlled vacuum. The digital model offers improved accuracy, repeatability, and ease of operation for pharmaceutical packaging quality control.",

        features: [
            "Microprocessor based digital vacuum measurement",
            "Digital vacuum display for precise readings",
            "Transparent acrylic vacuum chamber",
            "User-friendly keypad operation",
            "Programmable vacuum hold time",
            "Suitable for strip packs, blister packs, bottles, and containers",
            "Improved accuracy and repeatability over manual model",
            "Low maintenance and robust construction"
  ],

        specifications: [
            "Chamber: Transparent acrylic vacuum chamber",
            "Display: Digital display",
            "Vacuum Range: As per model configuration",
            "Operation: Automatic",
            "Timer: Programmable digital timer",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
  ],
        photo: "./Images/LEAK TEST APPARATUS RLT-2B.png",
        addons: [
            { code: "BAR-01", name: "Barcode scanner module", price: 8000 },
            { code: "TMP-01", name: "Temperature control module", price: 22000 }
        ],
        warranty_months: 24
    },
    {
        id: "TAT",
        name: "Tablet Dissolution Tester",
        price: 45000,
        currency: "INR",
        description: "Tablet Dissolution Tester is used to determine the rate at which active pharmaceutical ingredients are released from tablets or capsules into a dissolution medium under controlled conditions. It is an essential instrument for quality control and formulation development in pharmaceutical laboratories.",

        features: [
            "Microprocessor based dissolution testing system",
            "User-friendly operation with digital control panel",
            "Uniform temperature control of water bath",
            "Accurate speed control of rotating shafts",
            "Transparent water bath for clear observation",
            "Compliance with USP, IP and BP standards",
            "Robust and durable construction suitable for continuous laboratory use"
  ],

        specifications: [
            "Stations: 6 / 8 stations (model dependent)",
            "Temperature Range: Ambient to 45°C",
            "Speed Range: 25 to 250 rpm",
            "Display: Digital display",
            "Operation: Automatic",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
        ],
        photo: "./Images/TABLET DISSOLUTION TESTER RLDT-08LM.png",
        addons: [
            { code: "GEL-01", name: "Horizontal gel tank system", price: 18000 },
            { code: "DOC-01", name: "UV transilluminator", price: 25000 }
        ],
        warranty_months: 12
    },
    {
        id: "TDA",
        name: "Tapped Density Apparatus",
        price: 165000,
        currency: "INR",
       description: "Tapped Density Apparatus is designed to determine the tapped density of powders and granules by subjecting a measuring cylinder to controlled tapping. It is widely used in pharmaceutical, chemical, and food industries for powder flow and density analysis.",

        features: [
            "Microprocessor based instrument for accurate tapped density measurement",
            "User-friendly operation with simple control panel",
            "Programmable number of taps",
            "Uniform tapping mechanism ensuring repeatability",
            "Compatible with standard measuring cylinders",
            "Compact and robust laboratory design",
            "Compliance with pharmacopoeial standards"
  ],

        specifications: [
            "Tap Height: As per pharmacopeial standards",
            "Number of Taps: Programmable",
            "Display: Digital display",
            "Operation: Automatic",
            "Application: Powder and granule density measurement",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
  ],
        photo: "./Images/TAPPED DENSITY APPARATUS TD-2.png",
        addons: [
            { code: "CAL-01", name: "Calibration set of 4", price: 3500 },
            { code: "PRN-01", name: "Additional thermal paper pack", price: 800 }
        ],
        warranty_months: 12
    },
    {
        id: "ESS",
        name: "Electromagnetic Sieve Shaker",
        price: 225000,
        currency: "INR",
        description: "Electromagnetic Sieve Shaker is designed for efficient and reproducible particle size analysis of powders and granules. It uses electromagnetic vibration to achieve uniform sieving, making it suitable for pharmaceutical, chemical, and food laboratories.",

        features: [
            "Electromagnetic drive system for consistent sieving action",
            "Uniform vibration ensuring accurate particle size separation",
            "User-friendly operation with digital control panel",
            "Suitable for dry sieving applications",
            "Robust and compact construction for laboratory use",
            "Low noise operation and minimal maintenance",
            "Compliance with pharmacopeial standards"
  ],

        specifications: [
            "Drive Type: Electromagnetic",
            "Operation: Automatic",
            "Application: Particle size analysis",
            "Sieving Motion: Vertical vibration",
            "Display: Digital display",
            "Power: 230V AC / 50Hz (Or) 110V AC / 60Hz on request"
  ],
        photo: "./Images/electromagnetic-sieve-shaker.png" ,// NOT AVI
        addons: [
            { code: "CAL-01", name: "Calibration set of 4", price: 3500 },
            { code: "PRN-01", name: "Additional thermal paper pack", price: 800 }
        ],
        warranty_months: 24
    },
    {
        id: "STV",
        name: "Scott Type Volumeter",
        price: 89000,
        currency: "INR",
        description: "Scott Type Volumeter is used to determine the bulk density of powders by allowing the sample to flow through a series of baffles into a measuring cup. It is commonly used in pharmaceutical, chemical, and powder metallurgy laboratories for flow and density analysis.",

        features: [
            "Designed as per standard Scott volumeter principle",
            "Provides accurate and reproducible bulk density measurements",
            "Simple and easy to operate",
            "Robust construction suitable for laboratory use",
            "Uniform powder flow through baffle arrangement",
            "Low maintenance and durable design"
  ],

        specifications: [
            "Application: Bulk density measurement of powders",
            "Construction: Metallic body with funnel and baffles",
            "Operation: Manual",
            "Measurement Method: Scott volumeter principle",
            "Standards: As per pharmacopeial requirements"
  ],
        photo: "./Images/scott-type-volumeter.png", // NOT AVI
        addons: [
            { code: "LMS-01", name: "LIMS integration package", price: 15000 },
            { code: "MOB-01", name: "Mobile stand with tablet mount", price: 5000 }
        ],
        warranty_months: 12
    },
    {
        id: "PFT",
        name: "Powder Flow Tester",
        price: 145000,
        currency: "INR",
        description: "Powder Flow Tester is designed to evaluate the flow properties of powders and granules, helping determine their suitability for processing and packaging. It is widely used in pharmaceutical and chemical laboratories for powder flowability assessment.",

        features: [
            "Accurate assessment of powder flow characteristics",
            "Simple and easy to operate",
            "Suitable for different types of powders and granules",
            "Robust and stable laboratory construction",
            "Provides reliable and repeatable results",
            "Low maintenance design"
  ],

        specifications: [
            "Application: Powder flow property testing",
            "Operation: Manual",
            "Construction: Rigid laboratory-grade material",
            "Measurement Type: Flowability evaluation",
            "Standards: As per pharmacopeial guidelines"
  ],
        photo: "./Images/powder-flow-tester.png", // NOT AVI  
        addons: [
            { code: "BAR-01", name: "Barcode scanner module", price: 8000 },
            { code: "TMP-01", name: "Temperature control module", price: 22000 }
        ],
        warranty_months: 24
    }
];

// Exchange rate
const EXCHANGE_RATE = 0.012; // INR->USD

// =========================
// DOM ELEMENTS (same as before)
const loginView = document.getElementById('login-view');
const appView = document.getElementById('app-view');
const finalBillView = document.getElementById('final-bill-view');
const pastBillsView = document.getElementById('past-bills-view');

const loginForm = document.getElementById('login-form');
const loginError = document.getElementById('login-error');
const logoutBtn = document.getElementById('logout-btn');

const productSearch = document.getElementById('product-search');
const productList = document.getElementById('product-list');
const productDetail = document.getElementById('product-detail');

const unitPriceInput = document.getElementById('unit-price');
const quantityInput = document.getElementById('quantity');
const warrantyInput = document.getElementById('warranty');
const addonsContainer = document.getElementById('addons-container');
const addToBillBtn = document.getElementById('add-to-bill');

const customNameInput = document.getElementById('custom-name');
const customPriceInput = document.getElementById('custom-price');
const addCustomChargeBtn = document.getElementById('add-custom-charge');
const customChargesList = document.getElementById('custom-charges-list');

const billItems = document.getElementById('bill-items');
const subtotalElement = document.getElementById('subtotal');
const customChargesTotalElement = document.getElementById('custom-charges-total');
const gstElement = document.getElementById('gst');
const totalElement = document.getElementById('total');

const currencySelector = document.getElementById('currency-selector');
const generateBillBtn = document.getElementById('generate-bill');
const saveDraftBtn = document.getElementById('save-draft');
const pastBillsBtn = document.getElementById('past-bills');

const backToAppBtn = document.getElementById('back-to-app');
const downloadPdfBtn = document.getElementById('download-pdf');
const backToAppPastBtn = document.getElementById('back-to-app-past');
const pastBillsList = document.getElementById('past-bills-list');

const finalBillContent = document.getElementById('final-bill-content');

// =========================
// APP STATE
let currentState = {
    selectedProduct: null,
    billItems: [],
    customCharges: [],
    quoteNumber: null,
    quoteDate: null
};

// =========================
// INIT
document.addEventListener('DOMContentLoaded', () => {
    loadSavedData();
    PRODUCT_CATALOG.forEach(p => {
        const b = getBase64(p.photo);
        if (b) p.photo = b;
    });
    renderProductList(PRODUCT_CATALOG);
    updateBillPreview();
});

// =========================
// Events
if (loginForm) loginForm.addEventListener('submit', handleLogin);
const loginButton = loginForm && loginForm.querySelector('button[type="submit"]');
if (loginButton) loginButton.addEventListener('click', function (e) { e.preventDefault(); e.stopPropagation(); handleLogin(e); });
if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

if (productSearch) productSearch.addEventListener('input', handleSearch);
if (addToBillBtn) addToBillBtn.addEventListener('click', handleAddToBill);
if (addCustomChargeBtn) addCustomChargeBtn.addEventListener('click', handleAddCustomCharge);

if (currencySelector) currencySelector.addEventListener('change', updateBillPreview);
if (generateBillBtn) generateBillBtn.addEventListener('click', handleGenerateBill);
if (saveDraftBtn) saveDraftBtn.addEventListener('click', handleSaveDraft);
if (pastBillsBtn) pastBillsBtn.addEventListener('click', handleViewPastBills);

if (backToAppBtn) backToAppBtn.addEventListener('click', () => switchView(appView));
if (backToAppPastBtn) backToAppPastBtn.addEventListener('click', () => switchView(appView));
if (downloadPdfBtn) downloadPdfBtn.addEventListener('click', async () => { await renderFinalBillWithJsPDF(true); });

// =========================
// AUTH
function handleLogin(e) {
    e && e.preventDefault && e.preventDefault();
    const userid = document.getElementById('userid') ? document.getElementById('userid').value : '';
    const password = document.getElementById('password') ? document.getElementById('password').value : '';
    if (String(userid) === String(VALID_USERID) && String(password) === String(VALID_PASSWORD)) {
        if (loginError) loginError.textContent = '';
        switchView(appView);
        loginForm && loginForm.reset();
    } else {
        if (loginError) loginError.textContent = 'Invalid credentials. Please try again.';
    }
}
function handleLogout() { switchView(loginView); }
function switchView(view) {
    if (!view) return;
    [loginView, appView, finalBillView, pastBillsView].forEach(v => { if (v) v.classList.remove('active'); });
    view.classList.add('active');
}

// =========================
// Product list + detail (unchanged)
function renderProductList(products) {
    if (!productList) return;
    productList.innerHTML = '';
    products.forEach(product => {
        const el = document.createElement('div');
        el.className = 'product-item';
        el.dataset.id = product.id;
        el.innerHTML = `
            <div class="product-item-header">
                <span class="product-item-name">${product.name}</span>
                <span class="product-item-id">${product.id}</span>
            </div>
            <div class="product-item-price">₹${product.price.toLocaleString()}</div>
        `;
        el.addEventListener('click', () => selectProduct(product));
        productList.appendChild(el);
    });
}
function selectProduct(product) {
    currentState.selectedProduct = { ...product };
    document.querySelectorAll('.product-item').forEach(i => i.classList.remove('selected'));
    const selectedEl = document.querySelector(`.product-item[data-id="${product.id}"]`);
    if (selectedEl) selectedEl.classList.add('selected');

    const photoEl = document.getElementById('detail-photo');
    if (photoEl) {
        const data = getBase64(product.photo) || product.photo;
        photoEl.src = data || '';
        photoEl.alt = product.name;
    }

    document.getElementById('detail-name').textContent = product.name;
    document.getElementById('detail-id').textContent = product.id;
    document.getElementById('detail-price').textContent = `Base Price: ₹${product.price.toLocaleString()}`;
    document.getElementById('detail-desc').textContent = product.description;

    const featuresList = document.getElementById('detail-features');
    if (featuresList) {
        featuresList.innerHTML = '';
        product.features.forEach(f => { const li = document.createElement('li'); li.textContent = f; featuresList.appendChild(li); });
    }

    const specsList = document.getElementById('detail-specs');
    if (specsList) {
        specsList.innerHTML = '';
        product.specifications.forEach(s => { const li = document.createElement('li'); li.textContent = s; specsList.appendChild(li); });
    }

    if (unitPriceInput) unitPriceInput.value = product.price;
    if (quantityInput) quantityInput.value = 1;
    if (warrantyInput) warrantyInput.value = product.warranty_months;

    renderAddons(product.addons);
    productDetail && productDetail.classList.remove('hidden');
}
function renderAddons(addons) {
    if (!addonsContainer) return;
    addonsContainer.innerHTML = '';
    addons.forEach(addon => {
        const el = document.createElement('div');
        el.className = 'addon-item';
        el.innerHTML = `
            <input type="checkbox" id="addon-${addon.code}" data-code="${addon.code}" data-price="${addon.price}">
            <label for="addon-${addon.code}">${addon.name} (+₹${addon.price})</label>
        `;
        addonsContainer.appendChild(el);
    });
}
function handleSearch() {
    if (!productSearch) return;
    const term = productSearch.value.toLowerCase();
    if (!term) { renderProductList(PRODUCT_CATALOG); return; }
    const filtered = PRODUCT_CATALOG.filter(p => p.name.toLowerCase().includes(term) || p.id.toLowerCase().includes(term));
    renderProductList(filtered);
}

// =========================
// Bill management (unchanged logic)
function handleAddToBill() {
    if (!currentState.selectedProduct) { alert('Please select a product first.'); return; }
    const unitPrice = parseFloat(unitPriceInput.value);
    const quantity = parseInt(quantityInput.value);
    const warranty = parseInt(warrantyInput.value);
    if (isNaN(unitPrice) || unitPrice <= 0) { alert('Please enter a valid unit price.'); return; }
    if (isNaN(quantity) || quantity <= 0) { alert('Please enter a valid quantity.'); return; }
    if (isNaN(warranty) || warranty < 0) { alert('Please enter a valid warranty period.'); return; }

    const selectedAddons = [];
    document.querySelectorAll('#addons-container input:checked').forEach(cb => {
        const code = cb.dataset.code;
        const price = parseFloat(cb.dataset.price);
        const name = cb.nextElementSibling.textContent.split(' (+')[0];
        selectedAddons.push({ code, name, price });
    });

    const lineAmount = unitPrice * quantity + selectedAddons.reduce((sum, a) => sum + a.price, 0) * quantity;

    const billItem = {
        id: Date.now().toString(),
        productId: currentState.selectedProduct.id,
        productName: currentState.selectedProduct.name,
        productPhoto: currentState.selectedProduct.photo,
        productDescription: currentState.selectedProduct.description,
        productFeatures: [...currentState.selectedProduct.features],
        productSpecifications: [...currentState.selectedProduct.specifications],
        unitPrice,
        quantity,
        warranty,
        addons: selectedAddons,
        lineAmount
    };

    currentState.billItems.push(billItem);
    updateBillPreview();
    quantityInput.value = 1;
    document.querySelectorAll('#addons-container input:checked').forEach(cb => cb.checked = false);
}

function handleAddCustomCharge() {
    const name = customNameInput.value.trim();
    const price = parseFloat(customPriceInput.value);
    if (!name) { alert('Please enter a charge name.'); return; }
    if (isNaN(price) || price <= 0) { alert('Please enter a valid price.'); return; }
    const customCharge = { id: Date.now().toString(), name, price };
    currentState.customCharges.push(customCharge);
    renderCustomCharges();
    updateBillPreview();
    customNameInput.value = '';
    customPriceInput.value = '';
}
function renderCustomCharges() {
    if (!customChargesList) return;
    customChargesList.innerHTML = '';
    currentState.customCharges.forEach(charge => {
        const el = document.createElement('div');
        el.className = 'custom-charge-item';
        el.innerHTML = `<span>${charge.name}: ₹${charge.price.toLocaleString()}</span><button class="remove-item" data-id="${charge.id}">×</button>`;
        el.querySelector('.remove-item').addEventListener('click', () => {
            currentState.customCharges = currentState.customCharges.filter(c => c.id !== charge.id);
            renderCustomCharges(); updateBillPreview();
        });
        customChargesList.appendChild(el);
    });
}
function updateBillPreview() {
    if (!billItems) return;
    billItems.innerHTML = '';
    currentState.billItems.forEach((item, index) => {
        const row = document.createElement('tr');
        let addonsText = '';
        if (item.addons.length > 0) {
            addonsText = `<div style="font-size: 0.85em; color: #666;">` + item.addons.map(a => `<div>+ ${a.name}</div>`).join('') + `</div>`;
        }
        const currency = currencySelector && currencySelector.value ? currencySelector.value : 'INR';
        const unitPrice = convertCurrency(item.unitPrice, currency);
        const lineAmount = convertCurrency(item.lineAmount, currency);

        row.innerHTML = `
            <td>${index + 1}</td>
            <td>${item.productName}${addonsText}</td>
            <td>${item.productId}</td>
            <td>${item.quantity}</td>
            <td>${formatCurrency(unitPrice, currency)}</td>
            <td>${formatCurrency(lineAmount, currency)}</td>
            <td>
                <button class="edit-item" data-id="${item.id}">✏️</button>
                <button class="remove-item" data-id="${item.id}">×</button>
            </td>
        `;
        row.querySelector('.edit-item').addEventListener('click', () => editBillItem(item));
        row.querySelector('.remove-item').addEventListener('click', () => { currentState.billItems = currentState.billItems.filter(i => i.id !== item.id); updateBillPreview(); });
        billItems.appendChild(row);
    });

    const currency = currencySelector && currencySelector.value ? currencySelector.value : 'INR';
    const subtotal = calculateSubtotal();
    const customChargesTotal = calculateCustomChargesTotal();
    const gst = (subtotal + customChargesTotal) * 0.18;
    const total = subtotal + customChargesTotal + gst;

    subtotalElement.textContent = formatCurrency(convertCurrency(subtotal, currency), currency);
    customChargesTotalElement.textContent = formatCurrency(convertCurrency(customChargesTotal, currency), currency);
    gstElement.textContent = formatCurrency(convertCurrency(gst, currency), currency);
    totalElement.textContent = formatCurrency(convertCurrency(total, currency), currency);
}
function calculateSubtotal() { return currentState.billItems.reduce((sum, i) => sum + i.lineAmount, 0); }
function calculateCustomChargesTotal() { return currentState.customCharges.reduce((sum, c) => sum + c.price, 0); }
function convertCurrency(amount, targetCurrency) { if (targetCurrency === 'USD') return amount * EXCHANGE_RATE; return amount; }

// ---------- deterministic currency formatter (no NBSP, plain ASCII) ----------
function formatCurrency(amount, currency) {
    if (amount === null || amount === undefined || isNaN(amount)) amount = 0;
    amount = Number(amount);

    function formatIndian(num) {
        const sign = num < 0 ? '-' : '';
        num = Math.abs(Math.round(num * 100) / 100); // round to 2 decimals
        const parts = num.toFixed(2).split('.');
        let intPart = parts[0];
        const decPart = parts[1];
        if (intPart.length > 3) {
            const last3 = intPart.slice(-3);
            let rest = intPart.slice(0, -3);
            // group rest in 2 digits
            rest = rest.replace(/\B(?=(\d{2})+(?!\d))/g, ",");
            intPart = rest + ',' + last3;
        }
        return sign + intPart + '.' + decPart;
    }

    function formatUS(num) {
        const sign = num < 0 ? '-' : '';
        num = Math.abs(Math.round(num * 100) / 100);
        const parts = num.toFixed(2).split('.');
        const intPart = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ",");
        return sign + intPart + '.' + parts[1];
    }

    if (currency === 'USD') return `$${formatUS(amount)}`;
    // default INR
    return `₹${formatIndian(amount)}`;
}

// edit item
function editBillItem(item) {
    const product = PRODUCT_CATALOG.find(p => p.id === item.productId);
    if (product) {
        selectProduct(product);
        unitPriceInput.value = item.unitPrice;
        quantityInput.value = item.quantity;
        warrantyInput.value = item.warranty;
        setTimeout(() => { item.addons.forEach(addon => { const cb = document.querySelector(`#addon-${addon.code}`); if (cb) cb.checked = true; }); }, 100);
    }
}

// =========================
// Preload images (base64-friendly)
async function preloadImages(urls = []) {
    const results = {};
    const placeholder = (text = 'No image') => {
        const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="400" height="300"><rect width="100%" height="100%" fill="#f5f5f5"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="#888" font-family="Arial" font-size="20">${text}</text></svg>`;
        return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
    };
    urls.forEach(u => {
        if (!u) { results[u] = placeholder('No image'); return; }
        const data = getBase64(u) || (typeof u === 'string' && u.startsWith('data:') ? u : null);
        results[u] = data || placeholder('No image');
    });
    return results;
}

// =========================
// Quote number generator
function generateQuoteNumber() {
    const today = new Date();
    const dateString = `${today.getFullYear()}${String(today.getMonth() + 1).padStart(2, '0')}${String(today.getDate()).padStart(2, '0')}`;
    const key = `rle_next_quote_${dateString}`;
    let nextNumber = parseInt(localStorage.getItem(key)) || 1;
    const quoteNumber = `RLE-Q-${dateString}-${String(nextNumber).padStart(4, '0')}`;
    localStorage.setItem(key, nextNumber + 1);
    return quoteNumber;
}

// generate bill
function handleGenerateBill() {
    if (currentState.billItems.length === 0) { alert('Please add at least one item to the bill.'); return; }
    currentState.quoteNumber = currentState.quoteNumber || generateQuoteNumber();
    currentState.quoteDate = new Date().toLocaleDateString('en-IN');
    finalBillContent.innerHTML = `<p>Your PDF quotation will open in a new tab as a preview and will also be saved automatically with the quote number.</p>`;
    switchView(finalBillView);
    renderFinalBillWithJsPDF(true);
}

// ---------- draw header with borders, larger logo, right-aligned heading ----------
function drawHeaderFirstPage(doc, PAGE_WIDTH, MARGIN, imgMap) {
    // Outer blue border
    doc.setDrawColor(37, 99, 235);
    doc.setLineWidth(1.2);
    doc.roundedRect(6, 6, PAGE_WIDTH - 12, 297 - 12, 3, 3, 'S');

    // Inner orange border
    doc.setDrawColor(249, 115, 22);
    doc.setLineWidth(0.8);
    doc.roundedRect(10, 10, PAGE_WIDTH - 20, 297 - 20, 2, 2, 'S');

    const innerLeft = MARGIN;
    const innerRight = PAGE_WIDTH - MARGIN;

    // Logo (bigger)
    const logoData = (imgMap && imgMap['logo']) || getBase64('logo');
    if (logoData) {
        try { doc.addImage(logoData, 'PNG', innerLeft, 14, 46, 22); }
        catch (e) { try { doc.addImage(logoData, 'JPEG', innerLeft, 14, 46, 22); } catch (e2) {} }
    } else {
        doc.setFontSize(12);
        doc.setFont(undefined, 'bold');
        doc.text(COMPANY_INFO.name, innerLeft, 22);
    }

    // Address (moved down)
    doc.setFontSize(9);
    doc.setFont(undefined, 'normal');
    const addrLines = COMPANY_INFO.address.split('\n');
    doc.text(addrLines, innerLeft, 42);

    // QUOTATION heading (right aligned)
    const headingRightX = innerRight;
    doc.setFontSize(18);
    doc.setFont(undefined, 'bold');
    doc.setTextColor(37, 99, 235);
    doc.text('QUOTATION', headingRightX, 28, { align: 'right' });

    doc.setFontSize(10);
    doc.setFont(undefined, 'normal');
    doc.setTextColor(0);
    doc.text(`Quote No: ${currentState.quoteNumber || ''}`, headingRightX, 34, { align: 'right' });
    doc.text(`Date: ${currentState.quoteDate || ''}`, headingRightX, 39, { align: 'right' });

    // separator moved lower
    const separatorY = 52;
    doc.setDrawColor(220);
    doc.setLineWidth(0.35);
    doc.line(innerLeft, separatorY, innerRight, separatorY);

    doc.setTextColor(0);
}

// =========================
// Main jsPDF renderer (fixed amount formatting + table overflow protection)
async function renderFinalBillWithJsPDF(forceDownload) {
    if (!window.jspdf) { alert('jsPDF not loaded.'); return; }
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'portrait' });

    const PAGE_WIDTH = 210;
    const PAGE_HEIGHT = 297;
    const MARGIN = 18;
    const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN;

    const logoKey = 'logo';
    const productImageKeys = currentState.billItems.map(it => it.productPhoto).filter(Boolean);
    const preloadKeys = [logoKey, ...productImageKeys];
    const imgMapLocal = await preloadImages(preloadKeys);

    const subtotal = calculateSubtotal();
    const customChargesTotal = calculateCustomChargesTotal();
    const gst = (subtotal + customChargesTotal) * 0.18;
    const total = subtotal + customChargesTotal + gst;
    const currency = (currencySelector && currencySelector.value) ? currencySelector.value : 'INR';

    let pageCount = 0;

    for (let i = 0; i < currentState.billItems.length; i++) {
        const item = currentState.billItems[i];

        if (i === 0) {
            drawHeaderFirstPage(doc, PAGE_WIDTH, MARGIN, imgMapLocal);
        } else {
            doc.addPage();
            // borders on subsequent pages
            doc.setDrawColor(37, 99, 235); doc.setLineWidth(1.2); doc.roundedRect(6, 6, PAGE_WIDTH - 12, PAGE_HEIGHT - 12, 3, 3, 'S');
            doc.setDrawColor(249, 115, 22); doc.setLineWidth(0.8); doc.roundedRect(10, 10, PAGE_WIDTH - 20, PAGE_HEIGHT - 20, 2, 2, 'S');
        }
        pageCount++;

        let y = (i === 0) ? 62 : 20;

        // Product name first
        doc.setFontSize(13); doc.setFont(undefined, 'bold');
        doc.text(`${i + 1}. ${item.productName}`, MARGIN, y);
        y += 8;

        // Center product image
        const productImgKey = item.productPhoto;
        const imgData = imgMapLocal[productImgKey] || getBase64(productImgKey) || (typeof productImgKey === 'string' && productImgKey.startsWith('data:') ? productImgKey : null);
        if (imgData) {
            const maxW = 84, maxH = 64;
            const imgX = (PAGE_WIDTH / 2) - (maxW / 2);
            try { doc.addImage(imgData, 'PNG', imgX, y, maxW, maxH); }
            catch (e) { try { doc.addImage(imgData, 'JPEG', imgX, y, maxW, maxH); } catch (e2) {} }
            y += maxH + 6;
        }

        // Description
        doc.setFontSize(10); doc.setFont(undefined, 'normal');
        const descLines = doc.splitTextToSize(item.productDescription || '', CONTENT_WIDTH);
        doc.text(descLines, MARGIN, y);
        y += descLines.length * 5 + 6;

        // Features & Specs side-by-side
        const leftX = MARGIN;
        const rightX = MARGIN + (CONTENT_WIDTH / 2) + 6;
        const colWidth = (CONTENT_WIDTH / 2) - 6;

        doc.setFont(undefined, 'bold'); doc.setFontSize(10);
        doc.text('Features:', leftX, y);
        doc.text('Specifications:', rightX, y);
        doc.setFont(undefined, 'normal'); doc.setFontSize(9);

        const featuresBullets = (item.productFeatures || []).map(f => '• ' + f);
        const specsBullets = (item.productSpecifications || []).map(s => '• ' + s);

        const leftLines = []; featuresBullets.forEach(line => doc.splitTextToSize(line, colWidth).forEach(l => leftLines.push(l)));
        const rightLines = []; specsBullets.forEach(line => doc.splitTextToSize(line, colWidth).forEach(l => rightLines.push(l)));

        let localY = y + 6;
        const rows = Math.max(leftLines.length, rightLines.length);
        for (let r = 0; r < rows; r++) {
            if (leftLines[r]) doc.text(leftLines[r], leftX, localY);
            if (rightLines[r]) doc.text(rightLines[r], rightX, localY);
            localY += 5;
        }
        y = localY + 6;

        // Product main table — widths tuned to give more space to numeric columns
        const unitPriceCur = convertCurrency(item.unitPrice, currency);
        const lineAmountCur = convertCurrency(item.unitPrice * item.quantity, currency);

        doc.autoTable({
            startY: y,
            head: [['Product ID', 'Description', 'Warranty', 'Qty', 'Unit Price', 'Amount']],
            body: [[
                item.productId,
                item.productName,
                `${item.warranty} months`,
                String(item.quantity),
                formatCurrency(unitPriceCur, currency),
                formatCurrency(lineAmountCur, currency)
            ]],
            theme: 'striped',
            styles: { fontSize: 9, cellPadding: 3, textColor: 0 },
            headStyles: { fillColor: [37, 99, 235], textColor: 255, fontStyle: 'bold' },
            columnStyles: {
                0: { cellWidth: 26 },  // Product ID
                1: { cellWidth: 50 },  // Description (smaller)
                2: { cellWidth: 20 },  // Warranty
                3: { cellWidth: 12, halign: 'center' }, // Qty
                4: { cellWidth: 36, halign: 'right' },  // Unit Price (wider)
                5: { cellWidth: 36, halign: 'right' }   // Amount (wider)
            },
            tableWidth: CONTENT_WIDTH - 2, // keep a tiny inner padding
            didParseCell: function (data) {
                // numeric columns must be plain, right-aligned and not too large font
                if (data.section === 'body' && (data.column.index === 4 || data.column.index === 5)) {
                    data.cell.styles.fontSize = 9;
                    data.cell.styles.halign = 'right';
                    data.cell.styles.cellPadding = 2;
                    data.cell.styles.overflow = 'ellipsize';
                }
                if (data.section === 'head' && (data.column.index === 4 || data.column.index === 5)) {
                    data.cell.styles.fontSize = 10;
                    data.cell.styles.fontStyle = 'bold';
                    data.cell.styles.halign = 'right';
                }
            }
        });
        y = doc.previousAutoTable.finalY + 6;

        // Addons table (similar tuning)
        if (item.addons && item.addons.length > 0) {
            const addonsBody = item.addons.map(a => {
                const up = convertCurrency(a.price, currency);
                const amt = convertCurrency(a.price * item.quantity, currency);
                return [
                    a.code,
                    a.name,
                    String(item.quantity),
                    formatCurrency(up, currency),
                    formatCurrency(amt, currency)
                ];
            });

            doc.autoTable({
                startY: y,
                head: [['Code', 'Name', 'Qty', 'Unit Price', 'Amount']],
                body: addonsBody,
                theme: 'grid',
                styles: { fontSize: 9, cellPadding: 3, textColor: 0 },
                headStyles: { fillColor: [37, 99, 235], textColor: 255, fontStyle: 'bold' },
                columnStyles: {
                    0: { cellWidth: 28 },
                    1: { cellWidth: 70 },
                    2: { cellWidth: 12, halign: 'center' },
                    3: { cellWidth: 36, halign: 'right' },
                    4: { cellWidth: 36, halign: 'right' }
                },
                tableWidth: CONTENT_WIDTH - 2,
                didParseCell: function (data) {
                    if (data.section === 'body' && (data.column.index === 3 || data.column.index === 4)) {
                        data.cell.styles.fontSize = 9;
                        data.cell.styles.halign = 'right';
                        data.cell.styles.overflow = 'ellipsize';
                    }
                    if (data.section === 'head' && (data.column.index === 3 || data.column.index === 4)) {
                        data.cell.styles.fontSize = 10;
                        data.cell.styles.fontStyle = 'bold';
                        data.cell.styles.halign = 'right';
                    }
                }
            });
            y = doc.previousAutoTable.finalY + 6;
        }

        // footer page number
        doc.setFontSize(9); doc.setTextColor(120);
        doc.text(`Page ${pageCount}`, PAGE_WIDTH / 2, PAGE_HEIGHT - 10, { align: 'center' });
        doc.setTextColor(0);
    }

    // Totals + Terms page
    doc.addPage();
    pageCount++;
    doc.setDrawColor(37, 99, 235); doc.setLineWidth(1.2); doc.roundedRect(6, 6, PAGE_WIDTH - 12, PAGE_HEIGHT - 12, 3, 3, 'S');
    doc.setDrawColor(249, 115, 22); doc.setLineWidth(0.8); doc.roundedRect(10, 10, PAGE_WIDTH - 20, PAGE_HEIGHT - 20, 2, 2, 'S');

    let fy = 26;
    doc.setFontSize(12); doc.setFont(undefined, 'bold'); doc.text('Summary', MARGIN, fy); fy += 10;

    const totalsX = PAGE_WIDTH - MARGIN - 90;
    doc.setFontSize(10); doc.setFont(undefined, 'normal');

    const rowsTot = [
        ['Subtotal:', formatCurrency(convertCurrency(subtotal, currency), currency)],
        ['Custom Charges:', formatCurrency(convertCurrency(customChargesTotal, currency), currency)],
        ['GST (18%):', formatCurrency(convertCurrency(gst, currency), currency)],
        ['Total:', formatCurrency(convertCurrency(total, currency), currency)]
    ];

    rowsTot.forEach((r, idx) => {
        doc.setFont(undefined, idx === rowsTot.length - 1 ? 'bold' : 'normal');
        doc.text(r[0], totalsX, fy);
        doc.text(r[1], PAGE_WIDTH - MARGIN - 4, fy, { align: 'right' });
        fy += 9;
    });

    fy += 8;
    doc.setFont(undefined, 'bold'); doc.setFontSize(11); doc.text('Terms & Conditions', MARGIN, fy); fy += 8;
    doc.setFont(undefined, 'normal'); doc.setFontSize(9);
    const tnc = [
        'HSN CODE: 84799031',
        'Taxes: 18% GST extra applicable',
        'Packaging & Forwarding: Extra as applicable',
        'Freight: Extra as applicable',
        'Delivery: 3-4 weeks from PO',
        'Installation: Extra as applicable',
        'Payment: 100% advance prior to dispatch',
        'Warranty: One year from dispatch'
    ];
    tnc.forEach(line => { const parts = doc.splitTextToSize('• ' + line, CONTENT_WIDTH - 30); doc.text(parts, MARGIN, fy); fy += parts.length * 5; });

    doc.setFontSize(10); doc.setFont(undefined, 'bold'); doc.text('For Raise Lab Equipment', PAGE_WIDTH - MARGIN - 50, PAGE_HEIGHT - 60);
    doc.setFont(undefined, 'normal'); doc.text('Sales Team', PAGE_WIDTH - MARGIN - 50, PAGE_HEIGHT - 55); doc.text('+91 91777 70365', PAGE_WIDTH - MARGIN - 50, PAGE_HEIGHT - 50);

    doc.setFontSize(9); doc.setTextColor(120); doc.text(`Page ${pageCount}`, PAGE_WIDTH / 2, PAGE_HEIGHT - 10, { align: 'center' });

    // Preview and auto-save with quote no (filename)
    try {
        const blobUrl = doc.output('bloburl');
        window.open(blobUrl, '_blank');
    } catch (e) {
        console.error(e);
    }

    const filename = `RLE-Quote-${currentState.quoteNumber || 'QUOTE'}.pdf`;
    try {
        doc.save(filename);
    } catch (e) {
        console.error('Save failed:', e);
    }

    return true;
}

// =========================
// Save / Load Drafts & Past Bills
function handleSaveDraft() {
    if (currentState.billItems.length === 0 && currentState.customCharges.length === 0) { alert('Nothing to save. Please add items first.'); return; }
    const draftId = `draft_${Date.now()}`; const draftDate = new Date().toLocaleDateString('en-IN');
    const subtotal = calculateSubtotal(); const customChargesTotal = calculateCustomChargesTotal(); const gst = (subtotal + customChargesTotal) * 0.18; const total = subtotal + customChargesTotal + gst;
    const draft = { id: draftId, date: draftDate, items: [...currentState.billItems], customCharges: [...currentState.customCharges], subtotal, customChargesTotal, gst, total };
    const drafts = JSON.parse(localStorage.getItem('rle_drafts') || '[]'); drafts.push(draft); localStorage.setItem('rle_drafts', JSON.stringify(drafts));
    alert('Draft saved successfully!');
}
function handleViewPastBills() { renderPastBills(); switchView(pastBillsView); }
function renderPastBills() {
    if (!pastBillsList) return;
    const bills = JSON.parse(localStorage.getItem('rle_bills') || '[]');
    const drafts = JSON.parse(localStorage.getItem('rle_drafts') || '[]');
    pastBillsList.innerHTML = '';
    if (bills.length === 0 && drafts.length === 0) { pastBillsList.innerHTML = '<p>No saved bills or drafts found.</p>'; return; }
    bills.forEach(bill => {
        const el = document.createElement('div'); el.className = 'bill-item';
        el.innerHTML = `<div class="bill-info"><h3>${bill.quoteNumber}</h3><div class="bill-meta"><span>Date: ${bill.date}</span><span>Total: ₹${bill.total.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span></div></div><div class="bill-actions-past"><button class="btn download-btn" data-id="${bill.quoteNumber}">Download</button></div>`;
        el.querySelector('.download-btn').addEventListener('click', () => downloadSavedBill(bill)); pastBillsList.appendChild(el);
    });
    drafts.forEach(draft => {
        const el = document.createElement('div'); el.className = 'bill-item';
        el.innerHTML = `<div class="bill-info"><h3>DRAFT - ${draft.date}</h3><div class="bill-meta"><span>Date: ${draft.date}</span><span>Total: ₹${draft.total.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span></div></div><div class="bill-actions-past"><button class="btn download-btn" data-id="${draft.id}">Load Draft</button></div>`;
        el.querySelector('.download-btn').addEventListener('click', () => loadDraft(draft)); pastBillsList.appendChild(el);
    });
}
function downloadSavedBill(bill) { alert(`This would regenerate and download ${bill.quoteNumber}.pdf (not implemented here).`); }
function loadDraft(draft) { currentState.billItems = [...draft.items]; currentState.customCharges = [...draft.customCharges]; renderCustomCharges(); updateBillPreview(); switchView(appView); alert('Draft loaded successfully!'); }
function loadSavedData() { /* placeholder */ }
