import os
import json
import pytest
from app import extract_indicators, make_final_decision, unshorten_url, load_knowledge_base

# 1. اختبار دالة تحميل قاعدة المعرفة والتأكد من احتوائها على كلمات مفتاحية
def test_load_knowledge_base():
    keywords = load_knowledge_base()
    assert isinstance(keywords, list)
    assert len(keywords) > 0
    assert "عاجل" in keywords

# 2. اختبار دالة استخراج المؤشرات من النصوص والروابط
def test_extract_indicators_with_phishing_text():
    sample_text = "عاجل جداً حسابك البنكي محظور اضغط هنا للتحديث https://fake-bank.com/login"
    indicators = extract_indicators(sample_text)
    
    assert indicators["has_urgency_words"] is True
    assert "https://fake-bank.com/login" in indicators["urls"]
    assert "fake-bank.com" in indicators["domains"]

# 3. اختبار دالة تتبع الروابط وتأمينها من السقوط في حال فشل الاتصال
def test_unshorten_url_fallback():
    # اختبار أن الدالة تعيد الرابط نفسه كحماية (Fallback) في حال كان الرابط وهمياً أو الشبكة معطلة
    bad_url = "https://non-existent-link-12345.xyz"
    result = unshorten_url(bad_url)
    assert result == bad_url

# 4. اختبار منطق اتخاذ القرار النهائي وحساب النسب المئوية الجديدة (3%، 50%، 98%)
@pytest.mark.parametrize("local_ind, api_res, llm_res, expected_status, expected_score", [
    # حالة الرابط الخطير المؤكد عبر VirusTotal
    (
        {"has_urgency_words": True},
        {"malicious": 3, "suspicious": 0},
        {"status": "safe", "reason": "تحليل مبدئي"},
        "dangerous",
        3
    ),
    # حالة الرابط المشبوه (منطقة رمادية)
    (
        {"has_urgency_words": True},
        {"notice": "لا توجد روابط خارجية."},
        {"status": "suspicious", "reason": "يحتوي لغة إلحاح"},
        "suspicious",
        50
    ),
    # حالة الرابط الآمن تماماً
    (
        {"has_urgency_words": False},
        {"malicious": 0, "suspicious": 0, "harmless": 70},
        {"status": "safe", "reason": "الرابط سليم"},
        "safe",
        98
    )
])
def test_make_final_decision(local_ind, api_res, llm_res, expected_status, expected_score):
    decision = make_final_decision(local_ind, api_res, llm_res)
    assert decision["status"] == expected_status
    assert decision["safety_score"] == expected_score
