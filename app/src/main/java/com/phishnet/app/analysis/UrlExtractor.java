package com.phishnet.app.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds link-like strings in free text. Nothing is fetched or resolved. Input and output are bounded.
 */
public final class UrlExtractor {

    public static final class Extraction {
        public final List<String> urls;
        /** The text was longer than {@link Limits#MAX_INPUT_CHARS}; only the start was read. */
        public final boolean textTruncated;
        /** More than {@link Limits#MAX_URLS} distinct links were found; the rest were ignored. */
        public final boolean tooManyUrls;

        Extraction(List<String> urls, boolean textTruncated, boolean tooManyUrls) {
            this.urls = urls;
            this.textTruncated = textTruncated;
            this.tooManyUrls = tooManyUrls;
        }
    }

    private static final String BODY = "[^\\s<>\"'`\\u201C\\u201D\\u2018\\u2019]";
    private static final Pattern CANDIDATE = Pattern.compile(
            "(?i)(?:[a-z][a-z0-9+.\\-]{1,19}://" + BODY + "+)"
                    + "|(?:\\b(?:javascript|vbscript):" + BODY + "+)"
                    + "|(?:\\bdata:[a-z]+/[a-z0-9.+\\-]+[;,]" + BODY + "*)"
                    + "|(?:\\bwww\\." + BODY + "+)"
                    + "|(?:\\b(?:[a-z0-9](?:[a-z0-9\\-]{0,61}[a-z0-9])?\\.){1,12}[a-z]{2,24}(?::\\d{1,5})?(?:[/?#]" + BODY + "*)?)");

    /** Bare names such as "example.com/login" are only accepted with one of these endings. */
    private static final Set<String> KNOWN_TLDS = new HashSet<>(Arrays.asList((
            "com,net,org,info,biz,io,co,in,us,uk,de,fr,ru,cn,jp,br,au,ca,app,dev,xyz,top,online,site,shop,store,club,"
                    + "live,link,click,cc,tk,ml,ga,cf,gq,me,ly,to,ws,vip,work,support,help,bank,finance,pay,icu,buzz,"
                    + "monster,cyou,sbs,cfd,zip,mov,tech,cloud,page,one,pw,su,ua,id,ng,pk,bd,lk,np,ae,sa,sg,my,ph,tw,"
                    + "hk,kr,th,vn,tr,it,es,nl,se,no,fi,dk,pl,cz,at,ch,be,pt,gr,ie,za,ke,eg,nz,mx,ar,cl,pe,gov,edu,"
                    + "mil,int,tv,fm,gl,ai,gg,ink,rest,quest,country,kim,loan,bid,men,date,download,stream,racing,"
                    + "review,party,trade,win,cam,sbi,bot,wiki,news,email,center,world,today,solutions,services,digital")
            .split(",")));

    public static Extraction extract(String text) {
        if (text == null || text.isEmpty()) {
            return new Extraction(new ArrayList<>(), false, false);
        }
        boolean truncated = text.length() > Limits.MAX_INPUT_CHARS;
        String s = truncated ? text.substring(0, Limits.MAX_INPUT_CHARS) : text;

        Set<String> found = new LinkedHashSet<>();
        boolean tooMany = false;
        Matcher m = CANDIDATE.matcher(s);
        while (m.find()) {
            if (Thread.currentThread().isInterrupted()) break;
            int start = m.start();
            if (start > 0 && s.charAt(start - 1) == '@') continue; // part of an e-mail address
            String c = trimTrailing(m.group());
            if (c.isEmpty()) continue;
            if (isBareDomain(c) && !hasKnownTld(c)) continue;
            if (found.size() >= Limits.MAX_URLS) {
                if (!found.contains(c)) tooMany = true;
                continue;
            }
            found.add(c);
        }
        return new Extraction(new ArrayList<>(found), truncated, tooMany);
    }

    private static boolean isBareDomain(String c) {
        String l = c.toLowerCase(Locale.ROOT);
        return !l.contains("://") && !l.startsWith("www.") && !l.startsWith("javascript:")
                && !l.startsWith("vbscript:") && !l.startsWith("data:");
    }

    private static boolean hasKnownTld(String c) {
        int end = c.length();
        for (int i = 0; i < c.length(); i++) {
            char ch = c.charAt(i);
            if (ch == ':' || ch == '/' || ch == '?' || ch == '#') {
                end = i;
                break;
            }
        }
        String host = c.substring(0, end).toLowerCase(Locale.ROOT);
        int dot = host.lastIndexOf('.');
        return dot >= 0 && KNOWN_TLDS.contains(host.substring(dot + 1));
    }

    private static String trimTrailing(String c) {
        int end = c.length();
        while (end > 0) {
            char ch = c.charAt(end - 1);
            if (".,;:!?'\"*>".indexOf(ch) >= 0) {
                end--;
            } else if (ch == ')' || ch == ']' || ch == '}') {
                char open = ch == ')' ? '(' : ch == ']' ? '[' : '{';
                int opens = 0;
                int closes = 0;
                for (int i = 0; i < end; i++) {
                    char x = c.charAt(i);
                    if (x == open) opens++;
                    else if (x == ch) closes++;
                }
                if (closes > opens) end--; else break;
            } else {
                break;
            }
        }
        return c.substring(0, end);
    }

    private UrlExtractor() {}
}
