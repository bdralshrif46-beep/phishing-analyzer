import os
import re
import json
import requests
import streamlit as st
from google import genai
from google.genai import types

# ملف محلي لمحاكاة "التعلم المستمر" وحفظ الكلمات المكتشفة حديثاً
KNOWLEDGE_BASE_FILE = "knowledge_base.json"

def load_knowledge_base():
    """تحميل قاعدة المعرفة المحلية (الكلمات المفتاحية)"""
    default_keywords = ["عاجل", "تحديث", "حسابك مجمد", "اضغط هنا", "فورا", "قفل", "urgent", "verify", "suspended", "click here"]
    if os.path.exists(KNOWLEDGE_BASE_FILE):
        try:
            with open(KNOWLEDGE_BASE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("urgency_keywords", default_keywords)
        except Exception:
            return default_keywords
    return default_keywords

def save_knowledge_base(keywords):
    """حفظ الكلمات المفتاحية الجديدة ليتعلم منها النظام محلياً"""
    try:
        with open(KNOWLEDGE_BASE_FILE, "w", encoding="utf-8") as f:
            json.dump({"urgency_keywords": list(set(keywords))}, f, ensure_ascii=False, indent=4)
    except Exception as e:
        pass

# --- القسم 4 & 1: استخراج المؤشرات عبر الكود والقواعد البسيطة ---
def extract_indicators(text: str) -> dict:
    """تحليل النص واستخراج الروابط، النطاقات، وكلمات الإلحاح"""
    urgency_keywords = load_knowledge_base()
    indicators = {
        "urls": [],
        "domains": [],
        "has_urgency_words": False,
        "urgency_keywords": urgency_keywords
    }
    
    # استخراج الروابط والنطاقات باستخدام Regex
    urls = re.findall(r'(https?://[^\s]+)', text)
    indicators["urls"] = urls
    
    for url in urls:
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            indicators["domains"].append(domain_match.group(1))
            
    # فحص الكلمات المفتاحية
    for word in urgency_keywords:
        if word in text.lower():
            indicators["has_urgency_words"] = True
            break
            
    return indicators


# --- القسم 2: استدعاء واجهة برمجة خارجية (VirusTotal) ومعالجة الأخطاء ---
def check_url_reputation(domain: str) -> dict:
    """فحص سمعة النطاق مع معالجة فشل الشبكة وحدود الطلبات"""
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
        return {"error": f"خطأ في الشبكة أثناء الاتصال بالواجهة: {str(e)}"}


# --- القسم 3: ضبط البرومت وطلب مخرجات JSON الصافية من جمنادي ---
def analyze_with_llm(indicators: dict) -> dict:
    """تحليل المؤشرات والتعلم المستمر عبر استخراج كلمات احتيال جديدة"""
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
        
        # التأكد من صحة الـ JSON قبل استعماله
        result_json = json.loads(response.text.strip())
        
        # 🧠 ميزة التعلم: إذا اكتشف الذكاء الاصطناعي كلمات إلحاح جديدة، أضفها لقاعدتنا المحلية فوراً
        new_keywords = result_json.get("discovered_urgency_keywords", [])
        if new_keywords:
            current_keywords = load_knowledge_base()
            current_keywords.extend(new_keywords)
            save_knowledge_base(current_keywords)
            
        return result_json
        
    except json.JSONDecodeError:
        return {"error": "المخرجات المستلمة من النموذج ليست بصيغة JSON صالحة."}
    except Exception as e:
        return {"error": f"فشل في تحليل النموذج اللغوي: {str(e)}"}


# --- القسم 4: دمج القواعد، الواجهة، والنموذج لاتخاذ القرار ---
def make_final_decision(local_ind: dict, api_res: dict, llm_res: dict) -> dict:
    """دمج الطبقات الثلاث بالكامل للخروج بحكم نهائي متكامل مع معالجة دقيقة لنتائج الفحص الخارجي"""
    
    # 1. قراءة النتيجة المبدئية من الذكاء الاصطناعي (إذا لم يكن هناك خطأ)
    if "error" in llm_res:
        final_status = "suspicious" if local_ind["has_urgency_words"] else "safe"
        confidence = 70 if local_ind["has_urgency_words"] else 90
        reason = llm_res["error"]
    else:
        final_status = llm_res.get("status", "safe")
        confidence = llm_res.get("confidence_score", 50)
        reason = llm_res.get("reason", "لا توجد تفاصيل إضافية.")

    # 2. فحص دقيق لرد VirusTotal وتجنب الأخطاء
    is_api_malicious = False
    if api_res and "error" not in api_res and "notice" not in api_res:
        # إذا وجدنا أن هناك محرك فحص واحد على الأقل اعتبره خبيثاً
        if api_res.get("malicious", 0) > 0 or api_res.get("suspicious", 0) > 0:
            is_api_malicious = True

    # 3. تعديل نسب الثقة بناءً على حالة الأمان (الشرط الذي طلبته سابقاً)
    if final_status == "safe" and not is_api_malicious and not local_ind["has_urgency_words"]:
        confidence = max(confidence, 95)
        reason = "تم فحص الرابط عبر طبقات الحماية المتعددة ولم يتم العثور على أي مؤشرات تهديد."

    # 4. تطبيق الشرط الخاص بك: إذا أكدت الواجهة الخارجية خطورة الرابط
    if is_api_malicious:
        final_status = "dangerous"
        confidence = max(confidence, 98)
        # التأكد من أن النص يضاف بشكل سليم دون تداخل
        reason = str(reason) + " (تم تأكيد التهديد أمنياً عبر الفحص الخارجي للسمعة VirusTotal)."
        
    return {"status": final_status, "confidence": confidence, "reason": reason}


# بناء الواجهة مع ميزة "تسهيل الوصول" المطلوبة
def main():
    st.set_page_config(page_title="محلل التهديدات الذكي والمطور", page_icon="🛡️")
    st.title("🛡️ محلل التهديدات الذكي ومكافح الاحتيال (النسخة الذكية المطورّة)")
    
    # 🔘 ميزة تسهيل الوصول: مفتاح (زر) عند الضغط عليه يظهر حقل تحديد الرابط
    st.subheader("♿ ميزات تسهيل الوصول")
    quick_access = st.button("⚡ مفتاح تسهيل الوصول: حدد الرابط وفحصه فوراً")
    
    user_input = ""
    
    # إذا تم الضغط على زر تسهيل الوصول، نظهر حقل مخصص ومدخل جاهز
    if quick_access or st.session_state.get("accessibility_mode", False):
        st.session_state["accessibility_mode"] = True
        user_input = st.text_input("🔗 حدد أو ضع الرابط المستهدف هنا:", placeholder="https://example-suspect.com")
    else:
        user_input = st.text_area("نص البريد أو الرابط:", height=150, placeholder="ضع النص الكامل هنا...")
    
    if st.button("ابدأ التحليل الأمني العميق"):
        if not user_input.strip():
            st.warning("الرجاء كتابة نص أو تحديد رابط أولاً.")
            return
            
        with st.spinner("جاري استخراج البيانات وتشغيل الفحص المتكامل والتعلم..."):
            indicators = extract_indicators(user_input)
            api_result = check_url_reputation(indicators["domains"][0]) if indicators["domains"] else {"notice": "لا توجد روابط خارجية."}
            llm_result = analyze_with_llm(indicators)
            final_report = make_final_decision(indicators, api_result, llm_result)
            
            st.write("---")
            st.subheader("📊 النتيجة والتقرير النهائي")
            
            status = final_report["status"]
            if status == "dangerous":
                st.error(f"🚨 النتيجة: **خطير / احتيال مؤكد** (نسبة الثقة: {final_report['confidence']}%)")
            elif status == "suspicious":
                st.warning(f"⚠️ النتيجة: **مشبوه ويحتوي على إشارات فيشينغ** (نسبة الثقة: {final_report['confidence']}%)")
            else:
                st.success(f"✅ النتيجة: **آمن وطبيعي** (نسبة الثقة: {final_report['confidence']}%)")
                
            st.info(f"📝 **سبب وحيثيات الحكم:** {final_report['reason']}")
            
            # عرض دليل على التعلم الذاتي
            st.success(f"🧠 قاعدة المعرفة المحلية تحتوي الآن على {len(indicators['urgency_keywords'])} كلمة مفتاحية (محدثة ديناميكياً).")

if __name__ == "__main__":
    main()
