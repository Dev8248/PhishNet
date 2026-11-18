package com.phishnet.app.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Built-in reference data. It is deliberately short, offline and static: it is NOT a threat feed,
 * it will be out of date, and it cannot know every legitimate or malicious domain.
 */
final class BrandData {

    static final class Brand {
        final String display;
        /** Lower-case names to look for. Names of 6+ letters match inside a label, shorter ones as a whole hyphen-token. */
        final String[] tokens;
        /** Registrable domains that really belong to the brand. "name.*" means name + a common country suffix. */
        final String[] official;

        Brand(String display, String tokens, String official) {
            this.display = display;
            this.tokens = tokens.split(",");
            this.official = official.split(",");
        }

        boolean isOfficial(String registrable) {
            for (String o : official) {
                if (o.endsWith(".*")) {
                    String base = o.substring(0, o.length() - 2);
                    if (registrable.startsWith(base + ".")
                            && COUNTRY_SUFFIXES.contains(registrable.substring(base.length() + 1))) {
                        return true;
                    }
                } else if (o.equals(registrable)) {
                    return true;
                }
            }
            return false;
        }

        List<String> exactOfficial() {
            List<String> out = new ArrayList<>();
            for (String o : official) {
                if (!o.endsWith(".*")) out.add(o);
            }
            return out;
        }
    }

    static final Set<String> COUNTRY_SUFFIXES = set(
            "com,net,org,in,co.in,uk,co.uk,de,fr,it,es,nl,ca,au,com.au,jp,co.jp,br,com.br,mx,com.mx,ae,sg,com.sg,"
                    + "se,pl,ch,at,be,pt,ie,nz,co.nz,za,co.za,tr,com.tr,hk,com.hk,tw,com.tw,kr,co.kr,eg,com.eg,"
                    + "sa,com.sa,pk,com.pk,bd,com.bd,lk,ng,com.ng,id,co.id,my,com.my,ph,com.ph,vn,ru");

    static final Brand[] BRANDS = {
            new Brand("PayPal", "paypal", "paypal.com,paypal.me,paypalobjects.com,paypal.*"),
            new Brand("Google", "google,gmail,youtube",
                    "google.com,google.*,gmail.com,googlemail.com,youtube.com,youtu.be,googleapis.com,"
                            + "googleusercontent.com,gstatic.com,ggpht.com,goo.gl,withgoogle.com,google-analytics.com,"
                            + "googlesyndication.com,googletagmanager.com,googleadservices.com,googlevideo.com,"
                            + "googlesource.com,g.co"),
            new Brand("Microsoft", "microsoft,outlook,office365,onedrive,hotmail,skype",
                    "microsoft.com,live.com,office.com,office365.com,outlook.com,hotmail.com,microsoftonline.com,"
                            + "windows.com,azure.com,skype.com,bing.com,msn.com,xbox.com,onedrive.com,microsoft365.com"),
            new Brand("Apple", "apple,icloud,itunes",
                    "apple.com,icloud.com,itunes.com,me.com,mzstatic.com,cdn-apple.com"),
            new Brand("Amazon", "amazon,amzn",
                    "amazon.com,amazon.*,amazonaws.com,amzn.com,amzn.to,amzn.in,amazonpay.in,primevideo.com,audible.com,a.co"),
            new Brand("Meta", "facebook,instagram,whatsapp",
                    "facebook.com,fb.com,fb.me,fbcdn.net,facebook.net,instagram.com,cdninstagram.com,whatsapp.com,"
                            + "whatsapp.net,messenger.com,meta.com,fb.watch"),
            new Brand("Netflix", "netflix", "netflix.com,nflxext.com,nflximg.net,nflxvideo.net,nflxso.net"),
            new Brand("LinkedIn", "linkedin", "linkedin.com,licdn.com,lnkd.in"),
            new Brand("Twitter/X", "twitter", "twitter.com,x.com,t.co,twimg.com"),
            new Brand("Dropbox", "dropbox", "dropbox.com,getdropbox.com,db.tt"),
            new Brand("DocuSign", "docusign", "docusign.com,docusign.net"),
            new Brand("Adobe", "adobe", "adobe.com,adobe.io,adobelogin.com,acrobat.com,adobesign.com,behance.net"),
            new Brand("Coinbase", "coinbase", "coinbase.com"),
            new Brand("Binance", "binance", "binance.com,binance.us"),
            new Brand("MetaMask", "metamask", "metamask.io,consensys.net"),
            new Brand("Trust Wallet", "trustwallet", "trustwallet.com"),
            new Brand("Spotify", "spotify", "spotify.com,scdn.co,spotifycdn.com"),
            new Brand("Discord", "discord", "discord.com,discord.gg,discordapp.com,discordapp.net"),
            new Brand("Telegram", "telegram", "telegram.org,t.me,telegram.me"),
            new Brand("GitHub", "github", "github.com,github.io,githubusercontent.com,githubassets.com"),
            new Brand("Steam", "steam,steampowered,steamcommunity",
                    "steampowered.com,steamcommunity.com,steamstatic.com"),
            new Brand("Zoom", "zoom", "zoom.us,zoom.com,zoomgov.com"),
            new Brand("Chase", "chase", "chase.com,jpmorganchase.com,jpmorgan.com"),
            new Brand("Bank of America", "bankofamerica", "bankofamerica.com,bofa.com"),
            new Brand("Wells Fargo", "wellsfargo", "wellsfargo.com,wf.com"),
            new Brand("Citi", "citibank,citi", "citi.com,citibank.com,citigroup.com"),
            new Brand("HSBC", "hsbc", "hsbc.com,hsbc.*"),
            new Brand("Barclays", "barclays", "barclays.com,barclays.co.uk,barclaycard.co.uk"),
            new Brand("DHL", "dhl", "dhl.com,dhl.de,dhl.*"),
            new Brand("FedEx", "fedex", "fedex.com"),
            new Brand("UPS", "ups", "ups.com"),
            new Brand("USPS", "usps", "usps.com,usps.gov"),
            new Brand("IRS", "irs", "irs.gov"),
            new Brand("Royal Mail", "royalmail", "royalmail.com"),
            new Brand("India Post", "indiapost", "indiapost.gov.in"),
            new Brand("State Bank of India", "sbi,onlinesbi",
                    "sbi.co.in,onlinesbi.sbi,onlinesbi.com,sbicard.com,sbilife.co.in"),
            new Brand("HDFC Bank", "hdfc,hdfcbank", "hdfcbank.com,hdfc.com,hdfclife.com,hdfcsec.com"),
            new Brand("ICICI Bank", "icici,icicibank",
                    "icicibank.com,icicidirect.com,icicilombard.com,iciciprulife.com"),
            new Brand("Axis Bank", "axisbank", "axisbank.com,axisbank.co.in"),
            new Brand("Kotak", "kotak", "kotak.com"),
            new Brand("Paytm", "paytm", "paytm.com,paytmbank.com"),
            new Brand("PhonePe", "phonepe", "phonepe.com"),
            new Brand("NPCI", "npci", "npci.org.in"),
            new Brand("UIDAI (Aadhaar)", "uidai,aadhaar", "uidai.gov.in"),
            new Brand("Income Tax India", "incometax", "incometax.gov.in,incometaxindia.gov.in"),
            new Brand("IRCTC", "irctc", "irctc.co.in"),
            new Brand("Flipkart", "flipkart", "flipkart.com,flixcart.com"),
            new Brand("Jio", "jio", "jio.com"),
            new Brand("Airtel", "airtel", "airtel.in,airtel.com"),
    };

    /** Common generic link shorteners. The real destination is hidden until the link is followed. */
    static final Set<String> SHORTENERS = set(
            "bit.ly,tinyurl.com,t.co,goo.gl,ow.ly,is.gd,buff.ly,rebrand.ly,cutt.ly,shorturl.at,t.ly,rb.gy,tiny.cc,"
                    + "lnkd.in,s.id,v.gd,bl.ink,soo.gd,bit.do,adf.ly,clck.ru,x.co,ift.tt,wp.me,shorte.st,short.io,"
                    + "qrco.de,qr.ae,trib.al,dlvr.it,snip.ly,lc.cx,u.to,kutt.it,po.st,mcaf.ee,su.pr,ouo.io,reurl.cc");

    /** Cheap or frequently abused top-level domains. Plenty of legitimate sites use them too. */
    static final Set<String> SUSPICIOUS_TLDS = set(
            "zip,mov,top,xyz,click,link,gq,tk,ml,cf,ga,work,support,country,kim,loan,rest,cyou,icu,buzz,monster,sbs,"
                    + "cfd,quest,bid,men,date,download,stream,racing,review,party,trade,win,cam");

    /** Free hosting, tunnelling and dynamic-DNS services: anyone can publish a page there. */
    static final Set<String> FREE_HOSTS = set(
            "duckdns.org,ddns.net,no-ip.com,no-ip.org,hopto.org,zapto.org,ngrok.io,ngrok-free.app,ngrok.app,"
                    + "trycloudflare.com,workers.dev,pages.dev,web.app,firebaseapp.com,github.io,gitlab.io,"
                    + "blogspot.com,weebly.com,wixsite.com,glitch.me,herokuapp.com,netlify.app,vercel.app,"
                    + "000webhostapp.com,infinityfreeapp.com,rf.gd,epizy.com,sites.google.com,appspot.com");

    /** Labels that look like a domain ending when they appear inside a subdomain. */
    static final Set<String> TLD_WORDS = set("com,net,org,gov,edu,info,co");

    static boolean isOfficialAny(String registrable) {
        for (Brand b : BRANDS) {
            if (b.isOfficial(registrable)) return true;
        }
        return false;
    }

    private static Set<String> set(String csv) {
        return new HashSet<>(Arrays.asList(csv.split(",")));
    }

    private BrandData() {}
}
