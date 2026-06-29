import os
import re
import json
import requests
import streamlit as st
from google import genai
from google.genai import types

# ملف قاعدة المعرفة المحلية للتعلم المستمر
KNOWLEDGE_BASE_FILE = "knowledge_base.json"

def load_knowledge_base():
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
    try:
        with open(KNOWLEDGE_BASE_FILE, "w", encoding="utf-8") as f:
            json.dump({"urgency_keywords": list(set(keywords))}, f, ensure_ascii=False, indent=4)
    except Exception:
        pass

def extract_indicators(text: str) -> dict:
    urgency_keywords = load_knowledge_base()
    indicators = {
        "urls": [],
        "domains": [],
        "has_urgency_words": False,
        "urgency_keywords": urgency_keywords
    }
    urls = re.findall(r'(https?://[^\s]+)', text)
    indicators["urls"] = urls
    for url in urls:
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            indicators["domains"].append(domain_match.group(1))
    for word in urgency_keywords:
        if word in text.lower():
            indicators["has_urgency_words"] = True
            break
    return indicators

def check_url_reputation(domain: str) -> dict:
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
    # قراءة الحالة المبدئية من تحليل الذكاء الاصطناعي
    if "error" in llm_res:
        final_status = "suspicious" if local_ind["has_urgency_words"] else "safe"
        reason = llm_res["error"]
    else:
        final_status = llm_res.get("status", "safe")
        reason = llm_res.get("reason", "لا توجد تفاصيل إضافية.")

    # التحقق من فحص السمعة العالمي VirusTotal
    is_api_malicious = False
    if api_res and "error" not in api_res and "notice" not in api_res:
        if api_res.get("malicious", 0) > 0 or api_res.get("suspicious", 0) > 0:
            is_api_malicious = True

    # إجبار الحالة لتكون خطيرة إذا أكد الفحص الخارجي ذلك
    if is_api_malicious:
        final_status = "dangerous"
        reason = str(reason) + " (تم تأكيد التهديد أمنياً عبر الفحص الخارجي للسمعة VirusTotal)."

    # 📊 احتساب "نسبة سلامة وأمان الرابط" :
    if final_status == "dangerous":
        safety_score = 3  # نسبة أمان منخفضة وقليلة جداً (3%) لأن الرابط تخريبي
    elif final_status == "suspicious":
        safety_score = 50  # نسبة أمان متوسطة (50%) لوجود مؤشرات خطر
    else:
        # إذا كان آمناً ولم يجد الفحص الخارجي أو المحلي أي مشكلة
        if not is_api_malicious and not local_ind["has_urgency_words"]:
            safety_score = 98  # درجة أمان عالية جداً (98%)
        else:
            safety_score = 85  # آمن لكن مع وجود بعض الملاحظات البسيطة

    return {"status": final_status, "safety_score": safety_score, "reason": reason}

def main():
    st.set_page_config(page_title="محلل التهديدات الذكي والمطور", page_icon="🛡️", layout="wide")
    
    # 📱 حقن الأكواد المسؤولة عن تحويل الموقع إلى تطبيق PWA قابل للتثبيت على الموبايل والكمبيوتر
    st.components.v1.html("""
    <script>
    // إنشاء ملف تعريف التطبيق (Manifest) برمجياً ليتعرف عليه الهاتف كتطبيق مستقل
    const manifest = {
      "name": "منظومة تحليل التهديدات الذكية",
      "short_name": "محلل التهديدات",
      "start_url": window.location.href,
      "display": "standalone",
      "background_color": "#1E1E2F",
      "theme_color": "#007BFF",
      "description": "تطبيق ذكي لفحص وتحليل الروابط والرسائل الاحتيالية بـ 3 طبقات حماية.",
      "icons": [
        {
          "src": "https://cdn-icons-png.flaticon.com/512/1041/1041844.png",
          "sizes": "512x512",
          "type": "image/png"
        }
      ]
    };
    
    const stringManifest = JSON.stringify(manifest);
    const blob = new Blob([stringManifest], {type: 'application/json'});
    const manifestURL = URL.createObjectURL(blob);
    
    let link = document.createElement('link');
    link.rel = 'manifest';
    link.href = manifestURL;
    document.head.appendChild(link);
    
    // تسجيل الـ Service Worker لتفعيل بيئة عمل التطبيقات المستقلة
    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('data:text/javascript;base64,c2VsZi5hZGRFdmVudExpc3RlbmVyKCdmZXRjaCcsIGZ1bmN0aW9uKGV2ZW50KSB7fSk7')
      .then(() => console.log('PWA Service Worker Active!'));
    }
    </script>
    """, height=0)

    # تحضير متغيرات الجلسة (Session State)
    if "report_ready" not in st.session_state:
        st.session_state["report_ready"] = False
        st.session_state["status"] = ""
        st.session_state["confidence"] = 0
        st.session_state["reason_ar"] = ""
        st.session_state["speech_text"] = ""
    
    if "show_accessibility_menu" not in st.session_state:
        st.session_state["show_accessibility_menu"] = False

    st.title("🛡️ منظومة تحليل التهديدات الذكية (نسخة التطبيق المثبت PWA)")
    
    # ♿ لوحة الوصول السريع وتسهيل الوصول
    if st.button("♿ لوحة الوصول السريع وتسهيل الوصول (افتح هنا)", use_container_width=True):
        st.session_state["show_accessibility_menu"] = not st.session_state["show_accessibility_menu"]

    if st.session_state["show_accessibility_menu"]:
        with st.expander("⚡ مركز الوصول السريع (المتحدث، المترجم، وفحص الرابط المباشر)", expanded=True):
            st.markdown("#### 🎯 أدخل الرابط أو النص هنا للفحص السريع:")
            quick_input = st.text_input("رابط سريع / نص بريد الكتروني:", placeholder="ضع الرابط هنا واضغط فحص...")
            
            if st.button("🔍 فحص سريع الآن", use_container_width=True):
                if quick_input.strip():
                    with st.spinner("جاري فحص مؤشرات الرابط..."):
                        indicators = extract_indicators(quick_input)
                        api_result = check_url_reputation(indicators["domains"][0]) if indicators["domains"] else {"notice": "لا توجد روابط خارجية."}
                        llm_result = analyze_with_llm(indicators)
                        final_report = make_final_decision(indicators, api_result, llm_result)
                        
                        st.session_state["report_ready"] = True
                        st.session_state["status"] = final_report["status"]
                        st.session_state["confidence"] = final_report["confidence"]
                        st.session_state["reason_ar"] = final_report["reason"]
                        
                        if final_report["status"] == "dangerous":
                            st.session_state["speech_text"] = f"تنبيه أمني. النتيجة خطيرة جداً واحتِيال مؤكد بنسبة ثقة {final_report['confidence']} في المئة."
                        elif final_report["status"] == "suspicious":
                            st.session_state["speech_text"] = f"تنبيه. النتيجة مشبوهة وتحتوي على إشارات احتيال بنسبة ثقة {final_report['confidence']} في المئة."
                        else:
                            st.session_state["speech_text"] = f"النتيجة آمنة وطبيعية تماماً بنسبة ثقة {final_report['confidence']} في المئة."
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
                        st.warning("الرجاء فحص رابط أولاً داخل مركز الوصول السريع لتتمكن من سماعه.")
            
            with col2:
                if st.button("🌐 ترجمة الحيثيات للإنجليزية فوراً", use_container_width=True):
                    if st.session_state["report_ready"]:
                        with st.spinner("جاري الترجمة الفورية عبر Gemini..."):
                            eng_text = translate_via_gemini(st.session_state["reason_ar"])
                            st.success(f"🇬🇧 **English:** {eng_text}")
                    else:
                        st.warning("لا توجد نتائج مترجمة بعد، قم بعمل فحص سريع أولاً.")

    # واجهة الإدخال التقليدية الكبيرة بالأسفل
    st.write("---")
    st.subheader("🖥️ واجهة الفحص التفصيلية الكاملة")
    user_input = st.text_area("ضع نص البريد الإلكتروني الكلي هنا للتحليل الموسع:", height=120)
    if st.button("تحليل موسع للبريد الكلي"):
        if user_input.strip():
            with st.spinner("جاري التحليل..."):
                indicators = extract_indicators(user_input)
                api_result = check_url_reputation(indicators["domains"][0]) if indicators["domains"] else {"notice": "لا توجد روابط خارجية."}
                llm_result = analyze_with_llm(indicators)
                final_report = make_final_decision(indicators, api_result, llm_result)
                st.session_state["report_ready"] = True
                st.session_state["status"] = final_report["status"]
                st.session_state["confidence"] = final_report["confidence"]
                st.session_state["reason_ar"] = final_report["reason"]
                st.session_state["speech_text"] = f"النتيجة تم تحديثها بناءً على الفحص الموسع."

    # عرض التقرير النهائي الموحد
    if st.session_state["report_ready"]:
        st.write("---")
        st.subheader("📊 التقرير الأمني وعوامل الثقة")
        status = st.session_state["status"]
        if status == "dangerous":
            st.error(f"🚨 النتيجة: **خطير / احتيال مؤكد** (نسبة الثقة: {st.session_state['confidence']}%)")
        elif status == "suspicious":
            st.warning(f"⚠️ النتيجة: **مشبوه ويحتوي على إشارات فيشينغ** (نسبة الثقة: {st.session_state['confidence']}%)")
        else:
            st.success(f"✅ النتيجة: **آمن وطبيعي** (نسبة الثقة: {st.session_state['confidence']}%)")
        st.info(f"📝 **حيثيات الحكم الأمنية:** {st.session_state['reason_ar']}")

if __name__ == "__main__":
    main()
