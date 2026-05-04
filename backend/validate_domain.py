from __future__ import annotations

import re
import time
from datetime import datetime, timezone

import requests
from bs4 import BeautifulSoup

from dns_resolver import query
from network_checks import scan_ports, ssl_details

PROTECTED_BRANDS=["google","microsoft","apple","amazon","facebook","twitter","paypal","netflix","instagram","linkedin","github","dropbox","salesforce","adobe","zoom","slack","discord","spotify"]


def _lev(a,b):
    dp=list(range(len(b)+1))
    for i,ca in enumerate(a,1):
        nd=[i]
        for j,cb in enumerate(b,1):
            nd.append(min(dp[j]+1,nd[-1]+1,dp[j-1]+(ca!=cb)))
        dp=nd
    return dp[-1]


def validate(ioc:dict)->dict:
    start=time.perf_counter(); d=ioc["value"].lower(); out={"ioc_id":ioc["ioc_id"],"type":"Domain","value":d,"risk_factors":[]}
    try:
        dns={k.lower():query(d,k) for k in ["A","AAAA","MX","NS","TXT"]}; out["dns"]=dns
        out["whois"]={"registrar":None,"created":None,"expires":None,"recently_registered":False,"expiring_soon":False,"privacy_protected":False}
        label=d.split('.')[0]; sim=None; dist=999
        for b in PROTECTED_BRANDS:
            dd=_lev(label,b)
            if dd<dist: dist,sim=dd,b
        out["typosquatting"]={"risk":dist<=2,"similar_to":sim,"distance":dist,"method":"levenshtein" if dist<=2 else None}
        out["ssl"]=ssl_details(d)
        rep={"spamhaus_dbl":bool(query(f"{d}.dbl.spamhaus.org","A")),"surbl":bool(query(f"{d}.multi.surbl.org","A")),"uribl":bool(query(f"{d}.multi.uribl.com","A"))}
        rep["any_listed"]=any(rep.values()); out["reputation"]=rep
        out["mail_security"]={"spf":{},"dmarc":{},"dkim":{},"bimi":{},"mta_sts":{},"tls_rpt":{}}
        out["ports"]=scan_ports(d,[80,443,8080,8443])
        content={"login_form_detected":False,"phishing_keywords":[],"redirect_count":0,"iframe_detected":False,"page_title":None}
        try:
            r=requests.get(f"http://{d}",timeout=3,headers={"User-Agent":"Mozilla/5.0"},allow_redirects=True)
            t=r.text.lower(); content["redirect_count"]=len(r.history)
            kws=[k for k in ["verify your account","confirm your identity","unusual sign-in","suspended","update your payment","click here to restore"] if k in t]
            content["phishing_keywords"]=kws; content["login_form_detected"]='<input type="password"' in t; content["iframe_detected"]="<iframe" in t
            soup=BeautifulSoup(r.text,"html.parser"); content["page_title"]=soup.title.text.strip() if soup.title else None
        except Exception:
            pass
        out["content"]=content
        score=(40 if rep["any_listed"] else 0)+(30 if out["typosquatting"]["risk"] else 0)+(20 if content["phishing_keywords"] else 0)
        out["risk_score"]=min(100,score)
        out["classification"]="typosquat" if out["typosquatting"]["risk"] else "malicious" if score>=70 else "suspicious" if score>=40 else "clean"
    except Exception as e:
        out.update({"error":str(e),"status":"check_failed"})
    out["validation_time_ms"]=int((time.perf_counter()-start)*1000); out["timestamp"]=datetime.now(timezone.utc).isoformat(); return out
