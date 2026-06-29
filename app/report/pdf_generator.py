from datetime import datetime
import os

def generate_pdf_report(data: dict, url: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recon_report_{timestamp}.pdf"
    filepath = os.path.join("static", "reports", filename)
    os.makedirs(os.path.join("static", "reports"), exist_ok=True)
    
    # Simple text report (PDF generation simplified)
    with open(filepath.replace('.pdf', '.txt'), 'w') as f:
        f.write(f"Recon Report for {url}\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write("=" * 50 + "\n")
        for key, value in data.items():
            f.write(f"{key}: {value}\n")
    
    return filepath.replace('.pdf', '.txt')
