# ── PDF Report Generator ──────────────────────────────────
# Professional PDF report generator with Crawling & JS Scanner details

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from datetime import datetime
import os

def generate_pdf_report(data: dict, url: str) -> str:
    """
    Generate professional PDF report from scan results
    Returns: Path to the generated PDF file
    """
    # Create PDF filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"recon_report_{timestamp}.pdf"
    filepath = os.path.join("static", "reports", filename)
    
    # Ensure reports directory exists
    os.makedirs(os.path.join("static", "reports"), exist_ok=True)
    
    # Create PDF document
    doc = SimpleDocTemplate(filepath, pagesize=A4, 
                            leftMargin=0.8*inch, rightMargin=0.8*inch,
                            topMargin=0.8*inch, bottomMargin=0.8*inch)
    styles = getSampleStyleSheet()
    
    # ── Custom Styles ──
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=20,
        fontName='Helvetica-Bold',
        alignment=1
    )
    
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor('#666666'),
        spaceAfter=20,
        fontName='Helvetica',
        alignment=1
    )
    
    section_style = ParagraphStyle(
        'Section',
        parent=styles['Heading2'],
        fontSize=14,
        textColor=colors.HexColor('#1a1a2e'),
        spaceAfter=8,
        spaceBefore=15,
        fontName='Helvetica-Bold'
    )
    
    normal_style = ParagraphStyle(
        'Normal',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#333333'),
        fontName='Helvetica'
    )
    
    label_style = ParagraphStyle(
        'Label',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#666666'),
        fontName='Helvetica-Bold'
    )
    
    value_style = ParagraphStyle(
        'Value',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#1a1a2e'),
        fontName='Helvetica'
    )
    
    danger_style = ParagraphStyle(
        'Danger',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#cc0000'),
        fontName='Helvetica-Bold'
    )
    
    success_style = ParagraphStyle(
        'Success',
        parent=styles['Normal'],
        fontSize=9,
        textColor=colors.HexColor('#006600'),
        fontName='Helvetica-Bold'
    )
    
    # ── Build Content ──
    content = []
    
    # ── Header ──
    content.append(Paragraph("WEB RECONNAISSANCE REPORT", title_style))
    content.append(Paragraph(f"Comprehensive Security & Technology Analysis", subtitle_style))
    content.append(Paragraph(f"<b>Target:</b> {url}", normal_style))
    content.append(Paragraph(f"<b>Generated:</b> {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}", normal_style))
    content.append(Spacer(1, 0.3*inch))
    content.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    content.append(Spacer(1, 0.3*inch))
    
    # ── SSL Section ──
    if data.get('ssl'):
        content.append(Paragraph("🔒 SSL/TLS Certificate", section_style))
        ssl = data['ssl']
        
        ssl_data = []
        ssl_data.append([Paragraph("Issued To", label_style), Paragraph(ssl.get('issued_to', 'N/A'), value_style)])
        ssl_data.append([Paragraph("Issued By", label_style), Paragraph(ssl.get('issued_by', 'N/A'), value_style)])
        ssl_data.append([Paragraph("Valid From", label_style), Paragraph(ssl.get('valid_from', 'N/A'), value_style)])
        ssl_data.append([Paragraph("Valid Until", label_style), Paragraph(ssl.get('valid_until', 'N/A'), value_style)])
        
        days = ssl.get('days_remaining', 0)
        if days and days < 30:
            days_text = Paragraph(f"{days} days ⚠️", danger_style)
        elif days and days < 90:
            days_text = Paragraph(f"{days} days", normal_style)
        else:
            days_text = Paragraph(f"{days} days ✅", success_style)
        ssl_data.append([Paragraph("Days Remaining", label_style), days_text])
        
        expired = ssl.get('is_expired', False)
        expired_text = Paragraph("YES ⚠️", danger_style) if expired else Paragraph("NO ✅", success_style)
        ssl_data.append([Paragraph("Expired", label_style), expired_text])
        
        ssl_table = Table(ssl_data, colWidths=[1.8*inch, 3.5*inch])
        ssl_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e0e0e0')),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f5f5f5')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        content.append(ssl_table)
        content.append(Spacer(1, 0.2*inch))
    
    # ── Security Headers Section ──
    if data.get('security_headers'):
        content.append(Paragraph("🛡️ Security Headers", section_style))
        sec = data['security_headers']
        score = sec.get('score', 0)
        
        if score >= 70:
            score_text = Paragraph(f"<b>Security Score: {score}/100</b> - GOOD ✅", success_style)
        elif score >= 40:
            score_text = Paragraph(f"<b>Security Score: {score}/100</b> - MEDIUM ⚠️", normal_style)
        else:
            score_text = Paragraph(f"<b>Security Score: {score}/100</b> - POOR ❌", danger_style)
        content.append(score_text)
        content.append(Spacer(1, 0.1*inch))
        
        if sec.get('present'):
            content.append(Paragraph("Present Headers:", normal_style))
            for header, value in sec['present'].items():
                content.append(Paragraph(f"✓ {header}: {value}", normal_style))
            content.append(Spacer(1, 0.1*inch))
        
        if sec.get('missing'):
            content.append(Paragraph("Missing Headers (Security Risk):", normal_style))
            missing_data = [[Paragraph(f"✗ {header}", danger_style), Paragraph("Missing", danger_style)] for header in sec['missing']]
            missing_table = Table(missing_data, colWidths=[2.5*inch, 1*inch])
            missing_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#ffcccc')),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fff5f5')),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 5),
            ]))
            content.append(missing_table)
        content.append(Spacer(1, 0.2*inch))
    
    # ── Port Scan Section ──
    if data.get('ports'):
        content.append(Paragraph("🔌 Port Scan Results", section_style))
        ports = data['ports']
        content.append(Paragraph(f"<b>Open Ports Found:</b> {ports.get('total_open', 0)}", normal_style))
        
        if ports.get('open_ports'):
            port_data = [[Paragraph("Port", label_style), Paragraph("Service", label_style), 
                          Paragraph("State", label_style), Paragraph("Version", label_style)]]
            for p in ports['open_ports']:
                port_data.append([
                    Paragraph(str(p.get('port', '')), normal_style),
                    Paragraph(p.get('service', ''), normal_style),
                    Paragraph(p.get('state', ''), normal_style),
                    Paragraph(p.get('version', '')[:40], normal_style)
                ])
            
            port_table = Table(port_data, colWidths=[0.7*inch, 1.2*inch, 0.7*inch, 2.7*inch])
            port_table.setStyle(TableStyle([
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            content.append(port_table)
        content.append(Spacer(1, 0.2*inch))
    
    # ── Firewall Section ──
    if data.get('firewall'):
        content.append(Paragraph("🧱 Firewall Detection", section_style))
        fw = data['firewall']
        if fw.get('detected'):
            content.append(Paragraph(f"<b>Status:</b> Firewall Detected ⚠️", normal_style))
            content.append(Paragraph(f"<b>Firewall:</b> {fw.get('firewall_name', 'Unknown')}", normal_style))
            content.append(Paragraph(f"<b>Evidence:</b> {fw.get('evidence', 'N/A')}", normal_style))
        else:
            content.append(Paragraph("✅ No Firewall Detected", success_style))
        content.append(Spacer(1, 0.2*inch))
    
    # ── Tech Detection ──
    if data.get('tech'):
        content.append(Paragraph("💻 Technology Stack", section_style))
        tech = data['tech']
        content.append(Paragraph(f"<b>Technologies Found:</b> {tech.get('total_found', 0)}", normal_style))
        
        if tech.get('technologies'):
            for category, techs in tech['technologies'].items():
                content.append(Paragraph(f"<b>{category}:</b> {', '.join(techs)}", normal_style))
        content.append(Spacer(1, 0.2*inch))
    
    # ── Crawling Results Section (NEW) ──
    if data.get('crawl'):
        content.append(Paragraph("🌐 Crawling Results", section_style))
        crawl = data['crawl']
        content.append(Paragraph(f"<b>Total Endpoints Found:</b> {crawl.get('total_found', 0)}", normal_style))
        
        if crawl.get('endpoints'):
            endpoints = crawl['endpoints']
            # Show all endpoints with status
            endpoint_data = [[Paragraph("URL", label_style), Paragraph("Method", label_style), 
                              Paragraph("Status", label_style), Paragraph("Content Type", label_style)]]
            
            for e in endpoints[:20]:  # First 20 endpoints
                status_code = e.get('status_code', 'N/A')
                status_text = str(status_code) if status_code else 'N/A'
                
                # Color code status
                status_style = normal_style
                if status_code and status_code >= 200 and status_code < 300:
                    status_style = success_style
                elif status_code and (status_code >= 400 or status_code >= 500):
                    status_style = danger_style
                
                endpoint_data.append([
                    Paragraph(e.get('url', '')[:60], normal_style),
                    Paragraph(e.get('method', 'GET'), normal_style),
                    Paragraph(status_text, status_style),
                    Paragraph(e.get('content_type', '')[:30], normal_style)
                ])
            
            if len(endpoint_data) > 1:
                endpoint_table = Table(endpoint_data, colWidths=[2.5*inch, 0.6*inch, 0.6*inch, 1.2*inch])
                endpoint_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('PADDING', (0, 0), (-1, -1), 3),
                ]))
                content.append(endpoint_table)
                
                if len(endpoints) > 20:
                    content.append(Paragraph(f"... and {len(endpoints) - 20} more endpoints", normal_style))
        content.append(Spacer(1, 0.2*inch))
    
    # ── Subdomain Discovery ──
    if data.get('subdomains'):
        content.append(Paragraph("🌐 Subdomain Discovery", section_style))
        sub = data['subdomains']
        content.append(Paragraph(f"<b>Subdomains Found:</b> {sub.get('total_found', 0)}", normal_style))
        
        if sub.get('subdomains'):
            sub_data = [[Paragraph("Subdomain", label_style), Paragraph("IP Address", label_style)]]
            for sd in sub['subdomains'][:20]:
                sub_data.append([
                    Paragraph(sd.get('subdomain', ''), normal_style),
                    Paragraph(sd.get('ip', 'N/A'), normal_style)
                ])
            
            if len(sub_data) > 1:
                sub_table = Table(sub_data, colWidths=[2.5*inch, 1.8*inch])
                sub_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('PADDING', (0, 0), (-1, -1), 4),
                ]))
                content.append(sub_table)
        content.append(Spacer(1, 0.2*inch))
    
    # ── JS Scanner Section (DETAILED) ──
    if data.get('js_scanner'):
        content.append(Paragraph("📜 JavaScript Scanner", section_style))
        js = data['js_scanner']
        content.append(Paragraph(f"<b>Total JS Files:</b> {js.get('total_js_files', 0)}", normal_style))
        
        # JS Files List with paths
        if js.get('js_files'):
            content.append(Paragraph("JavaScript Files Found:", normal_style))
            js_file_data = [[Paragraph("File Name", label_style), Paragraph("Full Path", label_style)]]
            
            for js_file in js['js_files'][:15]:
                url_path = js_file.get('url', '')
                file_name = url_path.split('/')[-1] if '/' in url_path else url_path
                js_file_data.append([
                    Paragraph(file_name[:30], normal_style),
                    Paragraph(url_path[:80], normal_style)
                ])
            
            if len(js_file_data) > 1:
                js_table = Table(js_file_data, colWidths=[1.2*inch, 3.5*inch])
                js_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('PADDING', (0, 0), (-1, -1), 3),
                ]))
                content.append(js_table)
        
        # Emails
        if js.get('emails'):
            content.append(Paragraph(f"📧 <b>Emails Found:</b> {', '.join(js['emails'])}", normal_style))
        
        # Internal Paths with details
        if js.get('internal_paths'):
            content.append(Paragraph("📁 Internal Paths Found:", normal_style))
            path_data = [[Paragraph("Path", label_style)]]
            for path in js['internal_paths'][:20]:
                path_data.append([Paragraph(path, normal_style)])
            
            if len(path_data) > 1:
                path_table = Table(path_data, colWidths=[4.5*inch])
                path_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cccccc')),
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f0f0f0')),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('PADDING', (0, 0), (-1, -1), 3),
                ]))
                content.append(path_table)
        
        # API Endpoints
        if js.get('api_endpoints'):
            content.append(Paragraph(f"📡 <b>API Endpoints:</b> {', '.join(js['api_endpoints'][:10])}", normal_style))
        
        # Social Media
        if js.get('social_media'):
            content.append(Paragraph(f"📱 <b>Social Media References:</b> {', '.join(js['social_media'][:5])}", normal_style))
        
        # Tokens (if any)
        if js.get('tokens'):
            content.append(Paragraph(f"🔑 <b>Potential Tokens/Keys:</b> {len(js['tokens'])} found", danger_style))
        
        content.append(Spacer(1, 0.2*inch))
    
    # ── Footer ──
    content.append(Spacer(1, 0.3*inch))
    content.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#cccccc')))
    content.append(Paragraph(f"Generated by Recon Tool v1.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8, 
                                         textColor=colors.HexColor('#999999'), alignment=1)))
    
    # Build PDF
    doc.build(content)
    return filepath