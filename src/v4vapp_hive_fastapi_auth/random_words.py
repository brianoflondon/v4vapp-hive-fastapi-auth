from enum import Enum
from typing import List
from mnemonic import Mnemonic


def get_closest_language(country_code):
    language_mapping = {
        "en": Language.english,
        "zh-CN": Language.chinese_simplified,
        "zh-TW": Language.chinese_traditional,
        "zh": Language.chinese_simplified,
        "fr": Language.french,
        "it": Language.italian,
        "ja": Language.japanese,
        "ko": Language.korean,
        "es": Language.spanish,
    }

    if country_code in language_mapping:
        return language_mapping[country_code]

    # Extract the language code from the country code
    language_code = country_code.split("-")[0]
    if language_code in language_mapping:
        return language_mapping[language_code]

    # If the exact language code doesn't exist, default to English
    return Language.english


class Language(str, Enum):
    english = "english"
    chinese_simplified = "chinese_simplified"
    chinese_traditional = "chinese_traditional"
    french = "french"
    italian = "italian"
    japanese = "japanese"
    korean = "korean"
    spanish = "spanish"


def generate_random_words(count: int, lang_code: str) -> List[str]:
    # Generate a random mnemonic
    lang = get_closest_language(lang_code)
    mnemonic = Mnemonic(lang.value)
    words = mnemonic.generate(strength=256)
    # Convert the mnemonic to a list of words
    word_list = words.split(" ")

    # Return the requested number of random words
    return word_list[:count]
