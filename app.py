import os
import re
import json
import requests
import streamlit as st
from google import genai
from google.genai import types

# اسم ملف قاعدة المعرفة المحلية المخصص لتخزين الكلمات الاحتيالية المكتشفة ديناميكياً
KNOWLEDGE_BASE_FILE = "knowledge_base.json"

# [ميزة 3] القائمة البيضاء المحلية للنطاقات العالمية الموثوقة لمنع الإنذارات الكاذبة وتوفير الطلبات
GLOBAL_WHITELIST = {
    "google.com", "microsoft.com", "apple.com", "github.com", "linkedin.com", 
    "twitter.com", "x.com", "facebook.com", "instagram.com", "gmail.com",
    "outlook.com", "amazon.com", "netflix.com", "wikipedia.org", "streamlit.io"
}

def load_knowledge_base():
    """تحميل قاعدة المعرفة المحلية (الكلمات المفتاحية الافتراضية أو المحدثة)."""
    default_keywords = [
        "عاجل", "تحديث", "حسابك مجمد", "حسابك موقوف", "اضغط هنا", "فورا", "قفل", "حظر", "بطاقتك محظورة", 
        "انقر هنا", "تحقق من حسابك", "تأكيد الهوية", "ربحت", "جائزة", "عقد عمل", "بريد طارئ", "تسجيل الدخول", 
        "تغيير كلمة المرور", "الغاء القفل", "سرقة", "اختراق", "امان حسابك", "مخالفة لسياسة", "تحديث البيانات", 
        "البنك المركزي", "تم تعليق", "تنبيه اخير", "فرصة اخيرة", "روابط الدفع", "فواتير معلقة", "شحن مجاني", 
        "وظيفة عن بعد", "استثمر الان", "اربح مال", "فحص الحساب", "التحقق البشري", "رابط امان", "توثيق الحساب",
        "urgent", "verify", "suspended", "click here", "fake", "phishing", "update", "frozen", "locked", 
        "account suspended", "verify now", "action required", "immediate action", "security alert", 
        "password reset", "login here", "claim reward", "you won", "prize", "invoice pending", "update details", 
        "bank alert", "card blocked", "final notice", "confirm identity", "secure link", "access denied", 
        "free gift", "make money", "work from home", "crypto bonus", "official support", "unauthorized login"
    ]
    if os.path.exists(KNOWLEDGE_BASE_FILE):
        try:
            with open(KNOWLEDGE_BASE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("urgency_keywords", default_keywords)
        except Exception:
            return default_keywords
    return default_keywords

def save_knowledge_base(keywords):
    """حفظ وتحديث قاعدة المعرفة مع منع التكرار."""
    try:
        with open(KNOWLEDGE_BASE_FILE, "w", encoding="utf-8") as f:
            json.dump({"urgency_keywords": list(set(keywords))}, f, ensure_ascii=False, indent=4)
    except Exception:
        pass

def unshorten_url(url: str) -> str:
    """
    [ميزة 2] تتبع الروابط متعدد المستويات (Multi-Hop Redirection Tracking):
    تتبع قفزات إعادة التوجيه المتتالية (حتى 5 مستويات) للوصول إلى الرابط النهائي الحقيقي.
    """
    current_url = url
    max_redirects = 5
    try:
        for _ in range(max_redirects):
            response = requests.head(current_url, allow_redirects=False, timeout=4)
            if 300 <= response.status_code < 400 and "Location" in response.headers:
                next_url = response.headers["Location"]
                # معالجة الروابط النسبية
                if next_url.startswith("/"):
                    from urllib.parse import urljoin
                    current_url = urljoin(current_url, next_url)
                else:
                    current_url = next_url
            else:
                break
        return current_url
    except Exception:
        return url

def extract_indicators(text: str) -> dict:
    """الطبقة الأولى: استخراج الروابط وتتبعها، جلب النطاقات، وفحص كلمات الهندسة الاجتماعية."""
    urgency_keywords = load_knowledge_base()
    indicators = {
        "original_urls": [],
        "urls": [],
        "domains": [],
        "has_urgency_words": False,
        "urgency_keywords": urgency_keywords,
        "is_whitelisted": False  # مؤشر لمعرفة ما إذا كان الرابط في القائمة البيضاء
    }
    
    raw_urls = re.findall(r'(https?://[^\s]+)', text)
    indicators["original_urls"] = raw_urls
    
    for url in raw_urls:
        real_url = unshorten_url(url)
        indicators["urls"].append(real_url)
        
        domain_match = re.search(r'https?://([^/]+)', real_url)
        if domain_match:
            domain = domain_match.group(1).lower()
            # تنظيف النطاق الفرعي مثل www.
            clean_domain = domain.replace("www.", "")
            indicators["domains"].append(clean_domain)
            
            # [ميزة 3] التحقق من القائمة البيضاء
            if clean_domain in GLOBAL_WHITELIST or any(clean_domain.endswith("." + white_dom) for white_dom in GLOBAL_WHITELIST):
                indicators["is_whitelisted"] = True
            
    for word in urgency_keywords:
        if word in text.lower():
            indicators["has_urgency_words"] = True
            break
    return indicators

def check_url_reputation(domain: str) -> dict:
    """الطبقة الثانية: فحص سمعة النطاق أمنياً عبر واجهة VirusTotal API."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "مفتاح API الخاص بـ VirusTotal غير موجود."}
    
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)
            }
        return {"error": "لا توجد بيانات متاحة لهذا الرابط حالياً."}
    except Exception:
        return {"error": "خطأ في الاتصال بفحص الروابط الخارجي."}

def analyze_with_llm(indicators: dict) -> dict:
    """الطبقة الثالثة: التحليل السياقي وجلب القرارات عبر Gemini 2.5 Flash."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return {"error": "مفتاح الـ API الخاص بـ Gemini غير مضبوط."}
    try:
        with open("prompts.json", "r", encoding="utf-8") as f:
            prompts = json.load(f)
        base_prompt = prompts["phishing_analysis_prompt"]
        full_prompt = base_prompt.format(indicators=json.dumps(indicators, ensure_ascii=False))
        
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=full_prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json")
        )
        
        result_json = json.loads(response.text.strip())
        
        new_keywords = result_json.get("discovered_urgency_keywords", [])
        if new_keywords:
            current_keywords = load_knowledge_base()
            current_keywords.extend(new_keywords)
            save_knowledge_base(current_keywords)
        return result_json
    except Exception as e:
        return {"error": f"فشل في تحليل الذكاء الاصطناعي: {str(e)}"}

def translate_via_gemini(text_to_translate: str) -> str:
    """ترجمة الحيثيات الأمنية التلقائية إلى الإنجليزية السيبرانية عبر Gemini."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return "Error: Gemini API key missing."
    try:
        client = genai.Client(api_key=api_key)
        prompt = f"Translate the following Arabic cyber security analysis details into clear English:\n\n{text_to_translate}"
        response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt)
        return response.text.strip()
    except Exception:
        return "تعذر إتمام الترجمة التلقائية حالياً."

def make_final_decision(local_ind: dict, api_res: dict, llm_res: dict) -> dict:
    """اتخاذ القرار النهائي الموحد وحساب نسبة سلامة الرابط بدقة (3%، 50%، 98%)."""
    # [ميزة 3] تجاوز الفحص إذا كان النطاق مدرجاً في القائمة البيضاء وحالته آمنة كلياً
    if local_ind.get("is_whitelisted", False):
        return {
            "status": "safe", 
            "safety_score": 98, 
            "reason": "تم تخطي الفحص الخارجي بنجاح لأن النطاق المستهدف مدرج ضمن القائمة البيضاء المحلية للنطاقات العالمية الموثوقة والمؤمنة."
        }

    if "error" in llm_res:
        final_status = "suspicious" if local_ind["has_urgency_words"] else "safe"
        reason = llm_res["error"]
    else:
        final_status = llm_res.get("status", "safe")
        reason = llm_res.get("reason", "لا توجد تفاصيل إضافية.")

    is_api_malicious = False
    if api_res and "error" not in api_res and "notice" not in api_res:
        if api_res.get("malicious", 0) > 0 or api_res.get("suspicious", 0) > 0:
            is_api_malicious = True

    if is_api_malicious:
        final_status = "dangerous"
        reason = str(reason) + " (تم تأكيد التهديد أمنياً عبر الفحص الخارجي للسمعة VirusTotal)."

    if final_status == "dangerous":
        safety_score = 3   
    elif final_status == "suspicious":
        safety_score = 50  
    else:
        if not is_api_malicious and not local_ind["has_urgency_words"]:
            safety_score = 98  
        else:
            safety_score = 85  

    return {"status": final_status, "safety_score": safety_score, "reason": reason}

def main():
    st.set_page_config(page_title="محلل التهديدات الذكي والمطور", page_icon="🛡️", layout="wide")
    
    # 📱 كود تهيئة وتفعيل تطبيق الـ PWA ليكون مستقلاً وقابلاً للتثبيت
    st.components.v1.html("""
    <script>
    const manifest = {
      "name": "منظومة تحليل التهديدات الذكية",
      "short_name": "محلل التهديدات",
      "start_url": window.location.href,
      "display": "standalone",
      "background_color": "#1E1E2F",
      "theme_color": "#007BFF",
      "description": "تطبيق ذكي لفحص وتحليل الروابط والرسائل الاحتيالية بـ 3 طبقات حماية.",
      "icons": [{"src": "https://cdn-icons-png.flaticon.com/512/1041/1041844.png", "sizes": "512x512", "type": "image/png"}]
    };
    const stringManifest = JSON.stringify(manifest);
    const blob = new Blob([stringManifest], {type: 'application/json'});
    const manifestURL = URL.createObjectURL(blob);
    let link = document.createElement('link');
    link.rel = 'manifest'; link.href = manifestURL; document.head.appendChild(link);
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('data:text/javascript;base64,c2VsZi5hZGRFdmVudExpc3RlbmVyKCdmZXRjaCcsIGZ1bmN0aW9uKGV2ZW50KSB7fSk7')
      .then(() => console.log('PWA Service Worker Active!'));
    }
    </script>
    """, height=0)

    # تهيئة متغيرات الجلسة وتأمين استقرارها
    if "report_ready" not in st.session_state:
        st.session_state["report_ready"] = False
        st.session_state["status"] = ""
        st.session_state["safety_score"] = 0 
        st.session_state["reason_ar"] = ""
        st.session_state["speech_text"] = ""
    
    if "show_accessibility_menu" not in st.session_state:
        st.session_state["show_accessibility_menu"] = False

    st.title("🛡️ منظومة تحليل التهديدات الذكية (النسخة الاحترافية المحدثة)")
    
    # ♿ لوحة الوصول السريع وتسهيل الوصول
    if st.button("♿ لوحة الوصول السريع وتسهيل الوصول (افتح هنا)", use_container_width=True):
        st.session_state["show_accessibility_menu"] = not st.session_state["show_accessibility_menu"]

    if st.session_state["show_accessibility_menu"]:
        with st.expander("⚡ مركز الوصول السريع (المتحدث، المترجم، وفحص الرابط المباشر)", expanded=True):
            st.markdown("#### 🎯 أدخل الرابط أو النص هنا للفحص السريع:")
            quick_input = st.text_input("رابط سريع / نص بريد الكتروني:", placeholder="تلقائياً سيتم تتبع الروابط المختصرة ومتعددة التوجيه...")
            
            if st.button("🔍 فحص سريع الآن", use_container_width=True):
                if quick_input.strip():
                    with st.spinner("جاري كشف الروابط وتتبعها وفحص المؤشرات..."):
                        indicators = extract_indicators(quick_input)
                        
                        # [ميزة 3] التحقق الذكي لتجنب إرسال طلبات الـ API للنطاقات الآمنة في القائمة البيضاء
                        if indicators.get("is_whitelisted", False):
                            api_result = {"notice": "مدرج في القائمة البيضاء."}
                            llm_result = {"status": "safe", "reason": "قائمة بيضاء"}
                        else:
                            api_result = check_url_reputation(indicators["domains"][0]) if indicators["domains"] else {"notice": "لا توجد روابط خارجية."}
                            llm_result = analyze_with_llm(indicators)
                            
                        final_report = make_final_decision(indicators, api_result, llm_result)
                        
                        st.session_state["report_ready"] = True
                        st.session_state["status"] = final_report["status"]
                        st.session_state["safety_score"] = final_report["safety_score"]
                        st.session_state["reason_ar"] = final_report["reason"]
                        
                        if final_report["status"] == "dangerous":
                            st.session_state["speech_text"] = f"تنبيه أمني. النتيجة خطيرة جداً واحتِيال مؤكد. مؤشر سلامة الرابط منخفض جداً ويساوي {final_report['safety_score']} في المئة."
                        elif final_report["status"] == "suspicious":
                            st.session_state["speech_text"] = f"تنبيه أمني. النتيجة مشبوهة ومقلقة. مؤشر سلامة الرابط متوسط ويساوي {final_report['safety_score']} في المئة."
                        else:
                            st.session_state["speech_text"] = f"النتيجة آمنة تماماً. مؤشر سلامة الرابط مرتفع جداً ويساوي {final_report['safety_score']} في المئة."
                else:
                    st.warning("يرجى كتابة أو لصق شيء أولاً.")

            st.markdown("----")
            st.markdown("#### 🛠️ أدوات المساعدة الصوتية واللغوية الفورية:")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔊 استمع لنتيجة الفحص (صوتياً)", use_container_width=True):
                    if st.session_state["report_ready"]:
                        clean_text = st.session_state["speech_text"] + " والسبب هو: " + st.session_state["reason_ar"].replace('"', "'")
                        st.components.v1.html(f"""
                            <script>
                            window.speechSynthesis.cancel();
                            var msg = new SpeechSynthesisUtterance("{clean_text}");
                            msg.lang = 'ar-SA';
                            window.speechSynthesis.speak(msg);
                            </script>
                        """, height=0)
                        st.toast("🔊 جاري نطق التقرير صوتاً...")
                    else:
                        st.warning("الرجاء فحص بريد أو رابط أولاً لسماعه.")
            with col2:
                if st.button("🌐 ترجمة الحيثيات للإنجليزية فوراً", use_container_width=True):
                    if st.session_state["report_ready"]:
                        with st.spinner("جاري الترجمة الفورية عبر Gemini..."):
                            eng_text = translate_via_gemini(st.session_state["reason_ar"])
                            st.success(f"🇬🇧 **English:** {eng_text}")
                    else:
                        st.warning("لا توجد نتائج مترجمة بعد، قم بعمل فحص أولاً.")

    # 🖥️ واجهة الفحص التفصيلية ودعم رفع الملفات
    st.write("---")
    st.subheader("🖥️ واجهة الفحص التفصيلية ودعم رفع الملفات")
    
    uploaded_file = st.file_uploader("📂 يمكنك رفع ملف بريد إلكتروني أو نصي لفحصه مباشرة:", type=["txt", "eml"])
    file_content = ""
    if uploaded_file is not None:
        try:
            file_content = uploaded_file.read().decode("utf-8")
            st.success("✅ تم تحميل محتوى الملف بنجاح وقراءته برمجياً!")
        except Exception:
            st.error("❌ حدث خطأ أثناء قراءة ترميز الملف، يرجى التأكد أنه بصيغة نصية سليمة.")

    user_input = st.text_area("نص البريد الإلكتروني الكلي المراد تحليله:", value=file_content, height=140)
    
    if st.button("تحليل موسع وشامل"):
        if user_input.strip():
            with st.spinner("جاري تشغيل طبقات الحماية وتتبع الروابط متعددة التوجيه..."):
                indicators = extract_indicators(user_input)
                
                # [ميزة 3] تخطي طلبات الـ API إذا كان في القائمة البيضاء
                if indicators.get("is_whitelisted", False):
                    api_result = {"notice": "مدرج في القائمة البيضاء."}
                    llm_result = {"status": "safe", "reason": "قائمة بيضاء"}
                else:
                    api_result = check_url_reputation(indicators["domains"][0]) if indicators["domains"] else {"notice": "لا توجد روابط خارجية."}
                    llm_result = analyze_with_llm(indicators)
                    
                final_report = make_final_decision(indicators, api_result, llm_result)
                
                st.session_state["report_ready"] = True
                st.session_state["status"] = final_report["status"]
                st.session_state["safety_score"] = final_report["safety_score"]
                st.session_state["reason_ar"] = final_report["reason"]
                st.session_state["speech_text"] = f"تم تحديث النتيجة بناءً على التحليل الموسع الحالي."
        else:
            st.warning("الرجاء كتابة نص أو رفع ملف أولاً.")

    # عرض التقرير ومؤشر السلامة المعدل
    if st.session_state["report_ready"]:
        st.write("---")
        st.subheader("📊 التقرير الأمني ومؤشر السلامة الرقمية")
        
        status = st.session_state["status"]
        safety_score = st.session_state["safety_score"]  
        reason_ar = st.session_state["reason_ar"]
        
        if status == "dangerous":
            st.error(f"🚨 النتيجة: **خطير / احتيال مؤكد** (مؤشر سلامة الرابط: {safety_score}%) - الرابط غير آمن تماماً!")
        elif status == "suspicious":
            st.warning(f"⚠️ النتيجة: **مشبوه ويحتوي على إشارات فيشينغ** (مؤشر سلامة الرابط: {safety_score}%) - يرجى الحذر.")
        else:
            st.success(f"✅ النتيجة: **آمن وطبيعي** (مؤشر سلامة الرابط: {safety_score}%) - يمكنك استخدامه باطمئنان.")
            
        st.info(f"📝 **حيثيات الحكم الأمنية:** {reason_ar}")

if __name__ == "__main__":
    main()
