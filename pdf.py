from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        # Header with orange background and white text
        self.set_fill_color(255, 156, 0)  # Orange background
        self.set_text_color(255, 255, 255)  # White text
        self.set_font('times', 'B', 16)  # Bold, large font
        self.cell(0, 10, 'File Upload Vulnerabilities in Web Applications', ln=True, align='C', fill=True)
        self.ln(10)

    def footer(self):
        # Footer with gray text
        self.set_y(-15)
        self.set_font('times', 'I', 10)
        self.set_text_color(128, 128, 128)  # Gray color
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def chapter_title(self, title):
        # Black background and orange text for chapter titles
        self.set_fill_color(10, 10, 10)  # Black background
        self.set_text_color(255, 156, 0)  # Orange text
        self.set_font('times', 'B', 14)
        self.cell(0, 10, title, ln=True, fill=True)
        self.ln(4)

    def chapter_body(self, body):
        # Black text on white background for body text
        self.set_font('times', '', 12)
        self.set_text_color(0, 0, 0)  # Black color
        self.multi_cell(0, 10, body)
        self.ln()

    def add_image(self, image_path, width):
        # Add image with padding
        self.image(image_path, w=width)
        self.ln(10)

    def add_payload(self, payload):
        # Add payload with dark background and orange text
        self.set_fill_color(0, 0, 0)  # Dark gray background
        self.set_text_color(0, 255, 0)  # Green text
        self.set_font('times', 'B', 12)  # Monospace font for terminal-like appearance
        self.multi_cell(0, 10, payload, fill=True)
        self.ln()

# Create a colorful and attractive PDF
pdf = PDF()
pdf.set_auto_page_break(auto=True, margin=15)
pdf.add_page()

# Title page with an image
pdf.set_font('times', 'B', 16)
pdf.set_text_color(19, 24, 66)  # Orange color
pdf.set_font('times', size=12)
intro = (
    "This document explores various methods to test file upload vulnerabilities during a penetration "
    "test. It includes examples, potential payloads, and techniques for assessing security risks in web "
    "applications. As always, ensure you have explicit permission before conducting any tests."
)
pdf.multi_cell(0, 10, txt=intro)

# Add decorative image (local image "lock.png")
pdf.add_image('lock.png', width=190)

# Chapter 1 - File Extension Spoofing
pdf.chapter_title("1. File Extension Spoofing")
spoofing_desc = (
    "This involves bypassing file extension restrictions by renaming a malicious file to a permitted extension. "
    "Some web applications check only the file extension rather than the actual content.\n\n"
    "Example: Uploading a PHP file as 'shell.php.jpg' and accessing it if the server allows."
)
pdf.chapter_body(spoofing_desc)
# Add Payload block
pdf.add_payload("Payload: A simple PHP reverse shell.")

# Chapter 2 - MIME-Type Manipulation
pdf.chapter_title("2. MIME-Type Manipulation")
mime_desc = (
    "Manipulating the 'Content-Type' header in the HTTP request to bypass server-side checks. Many servers "
    "rely on this header to validate file types.\n\n"
    "Example: Changing the Content-Type of a .php file to 'image/png' using Burp Suite."
)
pdf.chapter_body(mime_desc)
# Add Payload block
pdf.add_payload("Payload: A PHP script that triggers a reverse shell.")

# Chapter 3 - Image Polyglot Files
pdf.chapter_title("3. Image Polyglot Files")
polyglot_desc = (
    "Embedding malicious code inside an image file to exploit applications that don't properly validate or "
    "parse image data.\n\n"
    "Example: Uploading a JPG file with embedded PHP code that runs when processed."
)
pdf.chapter_body(polyglot_desc)
# Add Payload block
pdf.add_payload("Payload: <?php system($_GET['cmd']); ?>")

# Chapter 4 - Directory Traversal in File Uploads
pdf.chapter_title("4. Directory Traversal in File Uploads")
dir_traversal_desc = (
    "Exploiting path traversal vulnerabilities to place files in sensitive directories. This can allow you to "
    "execute files or gain access to restricted areas.\n\n"
    "Example: Uploading a file as '../../uploads/shell.php' to place it in a higher directory."
)
pdf.chapter_body(dir_traversal_desc)
# Add Payload block
pdf.add_payload("Payload: A PHP reverse shell like php-reverse-shell.php.")

# Chapter 5 - Local/Remote File Inclusion (LFI/RFI)
pdf.chapter_title("5. Local/Remote File Inclusion (LFI/RFI)")
lfi_rfi_desc = (
    "Using file upload functionality to exploit Local or Remote File Inclusion vulnerabilities, leading to the "
    "execution of arbitrary code.\n\n"
    "Example: Uploading a .php file and accessing it via an LFI vulnerability to trigger code execution."
)
pdf.chapter_body(lfi_rfi_desc)
# Add Payload block
pdf.add_payload("Payload: <?php system('ls'); ?>")

# Chapter 6 - Metadata Injection
pdf.chapter_title("6. Metadata Injection")
metadata_desc = (
    "Injecting malicious metadata, such as EXIF data, into image files. When the server processes or displays "
    "the metadata, it can trigger Cross-Site Scripting (XSS) or code execution.\n\n"
    "Example: Uploading a JPG image with malicious EXIF data that triggers JavaScript execution."
)
pdf.chapter_body(metadata_desc)

# Chapter 7 - File Processing Exploits
pdf.chapter_title("7. File Processing Exploits")
file_proc_desc = (
    "Exploiting vulnerabilities in server-side services that process uploaded files, such as image or document "
    "conversion tools.\n\n"
    "Example: Exploiting vulnerabilities in libraries like ImageMagick by uploading a crafted file."
)
pdf.chapter_body(file_proc_desc)
# Add Payload block
pdf.add_payload("Payload: A malicious image designed to exploit ImageMagick (ImageTragick).")

# Chapter 8 - Multipart Form Data Tampering
pdf.chapter_title("8. Multipart Form Data Tampering")
multipart_desc = (
    "Modifying the content of a multipart form data request to bypass file restrictions or inject malicious data."
    "\n\nExample: Using Burp Suite to alter headers in a file upload request."
)
pdf.chapter_body(multipart_desc)

# Chapter 9 - Compressed File Uploads
pdf.chapter_title("9. Compressed File Uploads")
compressed_desc = (
    "Uploading compressed files (e.g., ZIP, TAR) containing malicious content. If the server extracts and processes "
    "the content without validation, it can lead to exploitation.\n\n"
    "Example: Uploading a ZIP file with a malicious PHP script inside."
)
pdf.chapter_body(compressed_desc)

# Chapter 10 - Disabling Client-Side Validation
pdf.chapter_title("10. Disabling Client-Side Validation")
client_side_desc = (
    "Bypassing client-side validation (e.g., JavaScript checks) by disabling it or intercepting and modifying the "
    "request. This allows the upload of otherwise restricted files.\n\n"
    "Example: Disabling JavaScript in the browser or using Burp Suite to manipulate the request."
)
pdf.chapter_body(client_side_desc)

# Chapter 11 - Cross-Site Scripting (XSS) in File Uploads
pdf.chapter_title("11. Cross-Site Scripting (XSS) in File Uploads")
xss_desc = (
    "Uploading files like SVG or HTML that contain XSS payloads. When viewed in a browser, they execute malicious "
    "JavaScript.\n\nExample: Uploading an SVG with a <script> tag to execute JavaScript."
)
pdf.chapter_body(xss_desc)

# Chapter 12 - Uploading Executable Payloads
pdf.chapter_title("12. Uploading Executable Payloads")
exec_payload_desc = (
    "Uploading executable files that contain malware or reverse shells. If executed on the server, this can give "
    "an attacker control over the system.\n\n"
    "Example: Uploading a compiled reverse shell binary."
)
pdf.chapter_body(exec_payload_desc)
# Add Payload block
pdf.add_payload("Payload: A PHP reverse shell like php-reverse-shell.php.")

# Save the updated colorful PDF
output_path = "file_upload_vulnerabilities_attractive.pdf"
pdf.output(output_path)

output_path