from __future__ import annotations
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet


def generate_pdf(session: dict) -> bytes:
    buff = BytesIO(); doc = SimpleDocTemplate(buff, pagesize=letter); styles = getSampleStyleSheet(); story=[]
    story += [Paragraph("NetIntel Enterprise Report", styles['Title']), Spacer(1, 12)]
    story += [Paragraph(f"Session: {session.get('session_id')}", styles['Normal']), Spacer(1, 8)]
    iocs=session.get('iocs',[])
    data=[["Type","Value","Risk","Classification"]]+[[i.get('type'),i.get('value'),i.get('risk_score','-'),i.get('classification','-')] for i in iocs[:100]]
    t=Table(data, repeatRows=1)
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#0A1A33')),('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#00E5FF')),('GRID',(0,0),(-1,-1),0.25,colors.grey)]))
    story.append(t)
    doc.build(story)
    return buff.getvalue()
