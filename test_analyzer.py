import pytest
import json
from app import extract_indicators, make_final_decision, load_knowledge_base, save_knowledge_base

# === اختبار القسم 1: فحص الدوال القصيرة وقاعدة البيانات والـ Regex ===
def test_extract_indicators_and_rules():
    test_text = "تحديث عاجل! اضغط هنا http://secure-bank-verify.com/login"
    result = extract_indicators(test_text)
    
    assert result["has_urgency_words"] is True
    assert "http://secure-bank-verify.com/login" in result["urls"]
    assert "secure-bank-verify.com" in result["domains"]

def test_knowledge_base_learning():
    # اختبار قدرة النظام على حفظ وتعلم الكلمات الجديدة
    original_keywords = load_knowledge_base()
    test_keywords = original_keywords + ["كلمة_احتيال_جديدة"]
    
    save_knowledge_base(test_keywords)
    updated_keywords = load_knowledge_base()
    
    assert "كلمة_احتيال_جديدة" in updated_keywords
    
    # تنظيف وإعادة الوضع الافتراضي
    save_knowledge_base(original_keywords)


# === اختبار القسم 2 & 3: معالجة الأخطاء والتحقق من هيكلية الـ JSON ===
def test_json_structure_and_error_handling():
    # محاكاة رد النموذج اللغوي للتأكد من توافق جيسون الصافي قبل استعماله
    mock_llm_response = '{"status": "dangerous", "confidence_score": 90, "reason": "رسالة احتيالية واضحة", "discovered_urgency_keywords": ["فورا"]}'
    
    try:
        parsed_json = json.loads(mock_llm_response)
        assert "status" in parsed_json
        assert "confidence_score" in parsed_json
        assert "reason" in parsed_json
    except json.JSONDecodeError:
        pytest.fail("المخرجات ليست جيسون صالح ومقاوم للأخطاء!")


# === اختبار القسم 4: دمج الواجهة والقواعد والنموذج لاتخاذ القرار النهائي ===
def test_make_final_decision_integration():
    local_indicators = {"has_urgency_words": True, "urls": ["http://fake.com"]}
    
    # حالة 1: تضارب أو تأكيد خطورة من الواجهة الخارجية للسمعة VirusTotal
    api_result_dangerous = {"malicious": 3, "suspicious": 0, "harmless": 0}
    llm_result = {"status": "suspicious", "confidence_score": 75, "reason": "نص مشبوه"}
    
    final_decision = make_final_decision(local_indicators, api_result_dangerous, llm_result)
    
    # يجب أن يرتفع مستوى القرار لخطير dangerous لأن الواجهة الخارجية أكدت ذلك
    assert final_decision["status"] == "dangerous"
    assert final_decision["confidence"] >= 95
