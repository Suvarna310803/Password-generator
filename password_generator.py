import secrets
import string

class PasswordGenerator:
    def generate(self, length=12, uppercase=True, lowercase=True, digits=True, symbols=True):
        character_set = ''
        if uppercase:
            character_set += string.ascii_uppercase
        if lowercase:
            character_set += string.ascii_lowercase
        if digits:
            character_set += string.digits
        if symbols:
            character_set += string.punctuation

        if not character_set:
            raise ValueError("At least one character set must be selected")

        return ''.join(secrets.choice(character_set) for _ in range(length))
