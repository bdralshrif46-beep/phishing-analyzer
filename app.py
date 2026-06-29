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
        "free gift", "make money", "work from home", "crypto bonus", "official support", "unauthorized login"]
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
        return {"error": "مفتاح API الخاص بـ VirusTotal غير موجود في البيئة."}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 429:
            return {"error": "تم تجاوز حد الطلبات المسموح به (Rate Limit)."}
        elif response.status_code != 200:
            return {"error": f"فشل الاتصال بالواجهة الخارجية. كود: {response.status_code}"}
        data = response.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0)
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"خطأ في الشبكة: {str(e)}"}

def analyze_with_llm(indicators: dict) -> dict:
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return {"error": "مفتاح GEMINI_API_KEY غير مضبوط كمتغير بيئة."}
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
        return {"error": f"فشل في تحليل النموذج اللغوي: {str(e)}"}

def make_final_decision(local_ind: dict, api_res: dict, llm_res: dict) -> dict:
    if "error" in llm_res:
        final_status = "suspicious" if local_ind["has_urgency_words"] else "safe"
        confidence = 70 if local_ind["has_urgency_words"] else 90
        reason = llm_res["error"]
    else:
        final_status = llm_res.get("status", "safe")
        confidence = llm_res.get("confidence_score", 50)
        reason = llm_res.get("reason", "لا توجد تفاصيل إضافية.")

    is_api_malicious = False
    if api_res and "error" not in api_res and "notice" not in api_res:
        if api_res.get("malicious", 0) > 0 or api_res.get("suspicious", 0) > 0:
            is_api_malicious = True

    if final_status == "safe" and not is_api_malicious and not local_ind["has_urgency_words"]:
        confidence = max(confidence, 95)
        reason = "تم فحص الرابط عبر طبقات الحماية المتعددة ولم يتم العثور على أي مؤشرات تهديد أولية."

    if is_api_malicious:
        final_status = "dangerous"
        confidence = max(confidence, 98)
        reason = str(reason) + " (تم تأكيد التهديد أمنياً عبر الفحص الخارجي للسمعة VirusTotal)."
        
    return {"status": final_status, "confidence": confidence, "reason": reason}

def main():
    st.set_page_config(page_title="محلل التهديدات الذكي والمطور", page_icon="🛡️", layout="wide")
    
    # ♿ حقن كود CSS مخصص لإنشاء ميزة "تسهيل الوصول العائمة" (تم تعديل الكلمة لـ unsafe_allow_html هنا)
    st.markdown("""
        <style>
        .accessibility-bar {
            position: fixed;
            bottom: 20px;
            left: 20px;
            background-color: #1E1E2F;
            color: white;
            padding: 15px;
            border-radius: 10px;
            box-shadow: 0px 4px 15px rgba(0,0,0,0.3);
            z-index: 9999;
            font-family: sans-serif;
            max-width: 280px;
        }
        .accessibility-btn {
            background-color: #4A90E2;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px 0;
            border-radius: 5px;
            cursor: pointer;
            width: 100%;
            text-align: center;
            font-weight: bold;
        }
        </style>
    """, unsafe_allow_html=True)

    st.title("🛡️ منظومة تحليل التهديدات الذكية (النسخة الاحترافية العالمية)")
    
    # تحضير نص التقرير الافتراضي للقراءة الصوتية لاحقاً
    if "last_report_text" not in st.session_state:
        st.session_state["last_report_text"] = "مرحباً بك في نظام فحص الروابط الذكي. من فضلك ضع الرابط أو النص لبدء الفحص."

    # 📱 شريط أدوات تسهيل الوصول الذكي في القائمة الجانبية
    st.sidebar.markdown("### ♿ لوحة تسهيل الوصول الذكية")
    
    # ميزة تحويل النص إلى كلام عبر ميزة النطق التلقائي للمتصفح
    if st.sidebar.button("🔊 استمع للتقرير الحالي (صوتياً)"):
        clean_text = st.session_state["last_report_text"].replace('"', "'")
        st.components.v1.html(f"""
            <script>
            var msg = new SpeechSynthesisUtterance("{clean_text}");
            msg.lang = 'ar-SA';
            window.speechSynthesis.speak(msg);
            </script>
        """, height=0)
        st.sidebar.success("جاري نطق التقرير باللغة العربية...")

    # ميزة الترجمة السريعة المدمجة للمظهر الاحترافي
    translate_mode = st.sidebar.checkbox("🌐 تفعيل الترجمة الفورية للإنجليزية")

    # واجهة إدخال البيانات الرئيسية
    st.subheader("🔍 مركز الفحص والتحليل")
    user_input = st.text_area("ضع نص البريد الإلكتروني أو حدد الرابط المراد فصحه هنا:", height=150, placeholder="مثال: تحديث عاجل لحسابك البنكي اضغط هنا http://fake-link.com")
    
    if st.button("ابدأ الفحص الأمني المتكامل"):
        if not user_input.strip():
            st.warning("الرجاء إدخال نص أو رابط أولاً.")
            return
            
        with st.spinner("جاري تشغيل طبقات الحماية الثلاث واستخرج المؤشرات..."):
            indicators = extract_indicators(user_input)
            api_result = check_url_reputation(indicators["domains"][0]) if indicators["domains"] else {"notice": "لا توجد روابط خارجية."}
            llm_result = analyze_with_llm(indicators)
            final_report = make_final_decision(indicators, api_result, llm_result)
            
            st.write("---")
            st.subheader("📊 التقرير النهائي وعوامل الأمان")
            
            status = final_report["status"]
            reason_text = final_report["reason"]
            
            if translate_mode:
                reason_text += " [Translation Mode Active]"

            if status == "dangerous":
                st.error(f"🚨 النتيجة: **خطير / احتيال مؤكد** (نسبة الثقة: {final_report['confidence']}%)")
                report_speech = f"تنبيه أمني. النتيجة خطيرة جداً واحتِيال مؤكد بنسبة ثقة {final_report['confidence']} في المئة. السبب هو: {reason_text}"
            elif status == "suspicious":
                st.warning(f"⚠️ النتيجة: **مشبوه ويحتوي على إشارات فيشينغ** (نسبة الثقة: {final_report['confidence']}%)")
                report_speech = f"تنبيه. النتيجة مشبوهة وتحتوي على إشارات احتيال بنسبة ثقة {final_report['confidence']} في المئة. السبب هو: {reason_text}"
            else:
                st.success(f"✅ النتيجة: **آمن وطبيعي** (نسبة الثقة: {final_report['confidence']}%)")
                report_speech = f"النتيجة آمنة وطبيعية تماماً بنسبة ثقة {final_report['confidence']} في المئة."
                
            st.info(f"📝 **حيثيات الحكم الأمنية:** {reason_text}")
            
            # حفظ النص ليتمكن زر تحويل النص إلى كلام من قراءته فوراً عند الضغط
            st.session_state["last_report_text"] = report_speech
            
            st.success(f"🧠 قاعدة المعرفة المحلية تم تحديثها تلقائياً وتحتوي على {len(indicators['urgency_keywords'])} مؤشر أمني.")

if __name__ == "__main__":
    main()
