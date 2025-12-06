# core/bert_model.py
from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline

# Модель на базі BERT, яка вміє робити мультимовний sentiment-analysis
MODEL_NAME = "nlptown/bert-base-multilingual-uncased-sentiment"

# Завантажуємо один раз при імпорті модуля
_tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
_model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)

_bert_sentiment = pipeline(
    "sentiment-analysis",
    model=_model,
    tokenizer=_tokenizer,
)


def analyze_text(text: str):
    """
    Повертає результат роботи BERT:
    {
        "label": "1 star" ... "5 stars",
        "score": 0.987
    }
    або None, якщо текст порожній.
    """
    if not text or not text.strip():
        return None

    # Зайве довгий текст ріжемо, щоб не було проблем з довжиною
    text = text.strip()
    if len(text) > 512:
        text = text[:512]

    result = _bert_sentiment(text)[0]

    # Приведемо до більш зручного формату
    label = result["label"]          # типу "4 stars"
    score = float(result["score"])   # ймовірність

    return {
        "label": label,
        "score": score,
    }
