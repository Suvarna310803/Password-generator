import re
import math

class PasswordStrengthAnalyzer:
    def analyze(self, password):
        length = len(password)

        has_uppercase = bool(re.search(r'[A-Z]', password))
        has_lowercase = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        entropy = self._calculate_entropy(password)

        if entropy > 60:
            return "VERY STRONG (🟢)"
        elif entropy > 40:
            return "STRONG (🟡)"
        elif entropy > 20:
            return "MODERATE (🟠)"
        else:
            return "WEAK (🔴)"

    def _calculate_entropy(self, password):
        char_set_size = sum([
            26 if re.search(r'[a-z]', password) else 0,
            26 if re.search(r'[A-Z]', password) else 0,
            10 if re.search(r'\d', password) else 0,
            32 if re.search(r'[!@#$%^&*(),.?":{}|<>]', password) else 0
        ])
        return len(password) * math.log2(char_set_size)
