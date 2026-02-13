import { jsPDF } from "jspdf"
import autoTable from "jspdf-autotable"

interface PDFData {
  quotation: any
  items: any[]
  settings: any
  user: any
  selectedTerms?: { title: string; text: string }[]
  currency?: 'INR' | 'USD'
}

export const generateQuotationPDF = async ({ quotation, items, settings, user, selectedTerms, currency = 'INR' }: PDFData) => {

  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4",
  })

  const pageWidth = doc.internal.pageSize.getWidth()
  const pageHeight = doc.internal.pageSize.getHeight()
  const margin = 15
  // Use text 'Rs.' instead of symbol if fonts are an issue, or ensure correct encoding.
  // The user reported "1" appearing, which is a common encoding issue with basic fonts in jsPDF.
  // Switching to 'Rs.' is the safest bet for immediate fix without loading custom fonts.
  const currencySymbol = currency === 'INR' ? 'Rs.' : '$'
  const currencyLabel = currency === 'INR' ? 'INR' : 'USD'

  const drawPageBorder = () => {
    // Outer Blue Border
    doc.setDrawColor(0, 82, 156)
    doc.setLineWidth(1.2)
    doc.rect(5, 5, pageWidth - 10, pageHeight - 10)

    // Inner Orange Border
    doc.setDrawColor(255, 102, 0)
    doc.setLineWidth(0.8)
    doc.rect(7, 7, pageWidth - 14, pageHeight - 14)

    // Footer contact box
    doc.setDrawColor(0, 0, 0)
    doc.setLineWidth(0.3)
    doc.rect(margin + 10, pageHeight - 20, pageWidth - (margin * 2) - 20, 8)
    doc.setFont("helvetica", "bold")
    doc.setFontSize(8)
    doc.setTextColor(0)
    doc.text("Write us: info@raiselabequip.com / sales@raiselabequip.com | Contact: +91 91777 70365", pageWidth / 2, pageHeight - 14.5, { align: "center" })
  }

  const drawHeader = (logoBase64: string) => {
    // Logo on top-left with increased dimensions for better fill
    if (logoBase64) {
      doc.addImage(logoBase64, "JPEG", margin, 12, 70, 25)
    }

    // Address on top-right - Formatted to fill space better
    doc.setFont("helvetica", "bold")
    doc.setFontSize(11)
    doc.setTextColor(0, 82, 156) // Raise Blue
    doc.text("RAISE LAB EQUIPMENT", pageWidth - margin, 18, { align: "right" })

    doc.setFont("helvetica", "normal")
    doc.setFontSize(9)
    doc.setTextColor(60)
    const address = "C-6, B1, Industrial Park, Moula Ali,\nHyderabad, Secunderabad,\nTelangana 500040"
    doc.text(address, pageWidth - margin, 24, { align: "right", lineHeightFactor: 1.4 })

    doc.setDrawColor(0, 82, 156)
    doc.setLineWidth(0.5)
    doc.line(margin, 42, pageWidth - margin, 42)
    doc.setDrawColor(255, 102, 0)
    doc.setLineWidth(0.3)
    doc.line(margin, 43, pageWidth - margin, 43)
  }

  // Pre-load quotation logo (use JPG)
  let logoBase64 = ""
  try {
    logoBase64 = await getBase64ImageFromURL('/quotation-logo.jpg')
  } catch (e) {
    console.warn("Could not load quotation logo", e)
  }

  // Pre-load item images in parallel with optimized caching
  const itemImages: Record<string, { base64: string; isWide: boolean }> = {}
  const imagePromises = items
    .filter(item => item.image_url)
    .map(async (item) => {
      try {
        const { base64, width, height } = await getBase64ImageWithDimensions(item.image_url!)
        const isWide = width > height * 1.3 // Consider wide if aspect ratio > 1.3
        itemImages[item.id] = { base64, isWide }
      } catch (e) {
        console.warn(`Could not load item image for ${item.id}`, e)
      }
    })

  await Promise.all(imagePromises)

  // Calculate total pages
  const totalPages = items.length + 1

  const drawPageNumber = (pageNum: number) => {
    doc.setFont("helvetica", "normal")
    doc.setFontSize(8)
    doc.setTextColor(0)
    doc.text(`Page ${pageNum} of ${totalPages}`, pageWidth - margin, pageHeight - 8, { align: "right" })
  }

  // Start Drawing
  let pageNumber = 1
  drawPageBorder()
  drawHeader(logoBase64)
  drawPageNumber(pageNumber)

  let currentY = 50
  let isFirstPage = true

  items.forEach((item, index) => {
    if (index > 0) {
      doc.addPage()
      pageNumber++
      drawPageBorder()
      drawHeader(logoBase64)
      drawPageNumber(pageNumber)
      currentY = 50
    }

    // "To" block - ONLY on first page, FIRST thing after header
    if (isFirstPage) {
      // Calculate validity date
      const validityDate = new Date(quotation.created_at || Date.now())
      validityDate.setDate(validityDate.getDate() + (quotation.validity_days || 30))

      const toAddress = `To\n\n${quotation.customer_name}${quotation.customer_address ? '\n' + quotation.customer_address : ''}`;

      const quoteNo = quotation.quotation_number;
      const dateStr = new Date(quotation.created_at || Date.now()).toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' }).replace(/\//g, '-');
      const validStr = validityDate.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' }).replace(/\//g, '-');

      autoTable(doc, {
        startY: currentY,
        body: [[
          {
            content: toAddress,
            styles: { fontStyle: "bold", fontSize: 10, valign: "top", cellPadding: 5 }
          },
          {
            content: `Quote No :  ${quoteNo}\nDate         :  ${dateStr}\nValidity    :  ${validStr}`,
            styles: { fontSize: 10, valign: "middle", cellPadding: 6, fontStyle: "bold" }
          }
        ]],
        theme: "grid",
        bodyStyles: {
          textColor: [0, 0, 0],
          lineColor: [0, 0, 0],
          lineWidth: 0.3,
          minCellHeight: 30,
        },
        columnStyles: {
          0: { cellWidth: pageWidth - (margin * 2) - 80, halign: "left" },
          1: { cellWidth: 80, halign: "left" }
        },
        margin: { left: margin, right: margin },
        tableWidth: pageWidth - (margin * 2)
      })
      currentY = (doc as any).lastAutoTable.finalY + 12
      isFirstPage = false
    }

    // Technical & Commercial Offer Title
    doc.setFont("helvetica", "bold")
    doc.setFontSize(14)
    doc.setTextColor(0, 82, 156)
    doc.text("Technical & Commercial Offer", pageWidth / 2, currentY, { align: "center" })
    currentY += 7
    doc.setFontSize(12)
    doc.setTextColor(0)
    doc.text(`For ${item.name}`, pageWidth / 2, currentY, { align: "center" })
    currentY += 12

    // Description section
    doc.setFont("helvetica", "bold")
    doc.setFontSize(10)
    doc.text("Description:", margin, currentY)
    currentY += 6
    doc.setFont("helvetica", "normal")
    doc.setFontSize(9)
    const splitDesc = doc.splitTextToSize(item.description || "", pageWidth - (margin * 2))
    doc.text(splitDesc, margin, currentY)
    currentY += (splitDesc.length * 5) + 5

    const imageData = itemImages[item.id]

    // Get features and image format option from item
    const imageFormat = item.image_format || 'wide' // 'wide' or 'tall'
    const features = item.features && item.features.length > 0 ? item.features : [
      "Accurate method for determining the strength of antibiotic material",
      "Microprocessor based design",
      "Average of Vertical diameter & Horizontal diameter of inhibited zone",
      "Magnified image of inhibited zone is clearly visible on the prism Screen",
      "Calibration facility with certified coins",
      "Inbuilt thermal printer",
      "Parallel printer port & RS 232 port for taking Test Printer Report",
      "Password protection for Real Time Clock",
      "Membrane Keypad for easy operation",
      "Complies to cGMP (MOC-stainless steel -304 & Stainless Steel-316)",
      "IQ/OQ Documentation"
    ]

    // Image layout based on admin selection
    if (imageFormat === 'wide') {
      // WIDE FORMAT: Image below description, then features
      if (imageData.base64) {
        // Ensure image fits within page width
        const imgWidth = pageWidth - (margin * 2) - 10
        const imgHeight = 65 // Increased height for better visibility
        doc.addImage(imageData.base64, "PNG", margin + 5, currentY, imgWidth, imgHeight)
        currentY += imgHeight + 10
      }

      // Features list below image
      doc.setFont("helvetica", "bold")
      doc.setFontSize(10)
      doc.text("FEATURES:", margin, currentY)
      currentY += 6

      doc.setFont("helvetica", "normal")
      doc.setFontSize(9)
      features.forEach((f: string) => {
        doc.text("•", margin + 3, currentY)
        const splitFeature = doc.splitTextToSize(f, pageWidth - (margin * 2) - 10)
        doc.text(splitFeature, margin + 8, currentY)
        currentY += splitFeature.length * 4.5
      })
      currentY += 5
    } else {
      // TALL FORMAT: Features on left, Image on right
      doc.setFont("helvetica", "bold")
      doc.setFontSize(10)
      doc.text("FEATURES:", margin, currentY)
      currentY += 6

      const featureStartY = currentY
      doc.setFont("helvetica", "normal")
      doc.setFontSize(9)

      // Calculate widths: Features get 55%, Image gets 40% approx
      const featureWidth = (pageWidth - (margin * 2)) * 0.55
      const imgWidth = (pageWidth - (margin * 2)) * 0.40

      features.forEach((f: string) => {
        doc.text("•", margin + 3, currentY)
        const splitFeature = doc.splitTextToSize(f, featureWidth)
        doc.text(splitFeature, margin + 8, currentY)
        currentY += splitFeature.length * 4.5
      })

      // Tall image on the right
      if (imageData?.base64) {
        const imgX = margin + featureWidth + 5
        const imgH = 75 // Increased height for side-by-side
        doc.addImage(imageData.base64, "JPEG", imgX, featureStartY, imgWidth, imgH)

        // Ensure new Y is below the taller of the two (features or image)
        const imageEndY = featureStartY + imgH + 10
        currentY = Math.max(currentY, imageEndY)
      } else {
        currentY += 5
      }
    }

    // Specification
    if (item.specs && item.specs.length > 0) {
      doc.setFont("helvetica", "bold")
      doc.setFontSize(10)
      doc.text("Specifications:", margin, currentY)
      currentY += 6
      doc.setFont("helvetica", "normal")
      doc.setFontSize(9)

      item.specs.forEach((s: { key: string; value: string }) => {
        doc.text("•", margin + 3, currentY)
        doc.setFont("helvetica", "bold")
        doc.text(s.key, margin + 8, currentY)
        doc.setFont("helvetica", "normal")
        doc.text(s.value.startsWith(":") ? s.value : `: ${s.value}`, margin + 55, currentY)
        currentY += 5
      })
      currentY += 5
    }

    // Check if we need a new page for commercial offer
    if (currentY > pageHeight - 60) {
      doc.addPage()
      drawPageBorder()
      drawHeader(logoBase64)
      currentY = 50
    }

    // Commercial Offer
    doc.setFont("helvetica", "bold")
    doc.setFontSize(11)
    doc.text("Commercial Offer:", margin, currentY)
    currentY += 6

    const tableRows = []

    // Calculate total price including add-ons
    const unitPrice = item.price + (item.selectedAddons?.reduce((s: number, a: any) => s + a.price, 0) || 0)

    // Description Cell Content
    let descContent = item.name
    if (item.selectedAddons && item.selectedAddons.length > 0) {
      descContent += "\n\nStandard Accessories:"
      item.selectedAddons.forEach((addon: any) => {
        descContent += `\n• ${addon.name}`
      })
    }

    tableRows.push([
      { content: "01", styles: { halign: "center", valign: "middle", fontSize: 10 } },
      { content: descContent, styles: { halign: "left", valign: "middle", fontSize: 10, cellPadding: 4 } },
      { content: "1", styles: { halign: "center", valign: "middle", fontSize: 10 } },
      { content: `${currencySymbol} ${unitPrice.toLocaleString('en-IN', { maximumFractionDigits: 2 })}/-`, styles: { halign: "center", fontStyle: "bold", valign: "middle", fontSize: 11, cellPadding: 4 } }
    ])

    autoTable(doc, {
      startY: currentY,
      head: [["S.No", "Description", "Qty", `Price (${currencyLabel})`]],
      body: tableRows,
      theme: "grid",
      headStyles: {
        fillColor: [0, 82, 156],
        textColor: [255, 255, 255],
        lineColor: [0, 0, 0],
        lineWidth: 0.2,
        fontStyle: "bold",
        halign: "center" as "center", // Explicit cast to fix type error
        fontSize: 10
      },
      bodyStyles: {
        textColor: [0, 0, 0],
        lineColor: [0, 0, 0],
        lineWidth: 0.2,
        fontSize: 10,
        cellPadding: 4
      },
      columnStyles: {
        0: { cellWidth: 15, halign: "center" },
        1: { cellWidth: "auto" },
        2: { cellWidth: 15, halign: "center" },
        // Increased width for price to prevent overflow
        3: { cellWidth: 50, halign: "center" }
      },
      margin: { left: margin, right: margin }
    })

    currentY = (doc as any).lastAutoTable.finalY + 10
  })

  // Terms & Conditions Page
  doc.addPage()
  pageNumber++
  drawPageBorder()
  drawHeader(logoBase64)
  drawPageNumber(pageNumber)

  currentY = 55 // Start terms higher up now that HSN is gone

  doc.setFont("helvetica", "bold")
  doc.setFontSize(12)
  doc.text("Terms And Conditions:", margin, currentY)
  currentY += 10

  // Default terms without numbering
  const defaultTerms = [
    { title: "Packaging & Forwarding", text: "Extra As Applicable" },
    { title: "Freight", text: "To Pay / Extra as applicable" },
    { title: "DELIVERY", text: "We deliver the order in 3-4 Weeks from the date of receipt of purchase order" },
    { title: "INSTALLATION", text: "Fees extra as applicable" },
    { title: "PAYMENT", text: "100% payment at the time of proforma invoice prior to dispatch." },
    { title: "WARRANTY", text: "One year warranty from the date of dispatch" },
    { title: "GOVERNING LAW", text: "These Terms and Conditions and any action related hereto shall be governed, controlled, interpreted and defined by and under the laws of the State of Telangana" },
    { title: "MODIFICATION", text: "Any modification of these Terms and Conditions shall be valid only if it is in writing and signed by the authorized representatives of both Supplier and Customer." }
  ]

  const termsToDisplay = selectedTerms && selectedTerms.length > 0 ? selectedTerms : defaultTerms;

  termsToDisplay.forEach((t) => {
    doc.setFont("helvetica", "normal")
    doc.setFontSize(9)

    // Remove any legacy number prefixes if present in custom terms
    const cleanTitle = t.title.replace(/^\d+\.\s*/, '');
    const fullText = `${cleanTitle}: ${t.text}`

    // Draw bullet point
    doc.text("•", margin, currentY)

    const splitT = doc.splitTextToSize(fullText, pageWidth - (margin * 2) - 5)
    doc.text(splitT, margin + 5, currentY)
    currentY += (splitT.length * 5) + 3
  })

  currentY += 15
  doc.setFont("helvetica", "bold")
  doc.setFontSize(10)
  doc.text(`From ${settings?.company_name || "Raise Lab Equipment"}`, pageWidth - margin, currentY, { align: "right" })
  currentY += 6
  doc.text(user?.full_name?.toUpperCase() || "SALES TEAM", pageWidth - margin, currentY, { align: "right" })
  currentY += 6
  doc.setFont("helvetica", "normal")
  doc.setFontSize(9)
  if (user?.phone) {
    doc.text(`Contact: ${user.phone}`, pageWidth - margin, currentY, { align: "right" })
  } else {
    doc.text("Contact: +91 91777 70365", pageWidth - margin, currentY, { align: "right" })
  }

  const pdfName = `${quotation.quotation_number}_Quotation.pdf`
  doc.save(pdfName)

  return doc.output("blob")
}

const getBase64ImageFromURL = (url: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.setAttribute("crossOrigin", "anonymous")
    img.onload = () => {
      const canvas = document.createElement("canvas")
      // Optimize: Reduce image size for PDFs (max width 800px)
      const maxWidth = 800
      const scale = img.width > maxWidth ? maxWidth / img.width : 1
      canvas.width = img.width * scale
      canvas.height = img.height * scale
      const ctx = canvas.getContext("2d")
      // Don't fill with black - keep transparent background
      if (ctx) {
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
      }
      // Use JPEG with 85% quality for smaller file size
      const dataURL = canvas.toDataURL("image/jpeg", 0.85)
      resolve(dataURL)
    }
    img.onerror = (error) => {
      reject(error)
    }
    img.src = url
  })
}

const getBase64ImageWithDimensions = (url: string): Promise<{ base64: string; width: number; height: number }> => {
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.setAttribute("crossOrigin", "anonymous")
    img.onload = () => {
      const canvas = document.createElement("canvas")
      // Optimize: Reduce image size for PDFs (max width 800px)
      const maxWidth = 800
      const scale = img.width > maxWidth ? maxWidth / img.width : 1
      canvas.width = img.width * scale
      canvas.height = img.height * scale
      const ctx = canvas.getContext("2d")
      // Don't fill with black - keep transparent background
      if (ctx) {
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
      }
      // Use JPEG with 85% quality for smaller file size
      const dataURL = canvas.toDataURL("image/jpeg", 0.85)
      resolve({ base64: dataURL, width: img.width, height: img.height })
    }
    img.onerror = (error) => {
      reject(error)
    }
    img.src = url
  })
}
