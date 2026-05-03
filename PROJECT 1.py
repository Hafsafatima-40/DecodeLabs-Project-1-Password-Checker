"""
Project 1: Password Strength Checker
Batch: 2026 | DecodeLabs
Cybersecurity Analyst - Defensive Phase
"""

import re
import hashlib
import hmac
import time

class PasswordStrengthChecker:
    """
    A comprehensive password strength checker that evaluates passwords
    based on multiple security criteria including length, character types,
    common patterns, and potential timing attack vulnerabilities.
    """
    
    def __init__(self):
        # Common weak passwords (simplified list for demonstration)
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'sunshine', 'iloveyou', 'football'
        }
        
        # Character sets for entropy calculation
        self.charsets = {
            'lowercase': 'abcdefghijklmnopqrstuvwxyz',
            'uppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'digits': '0123456789',
            'special': '!@#$%^&*()_+-=[]{}|;:,.<>?/~`'
        }
        
    def calculate_entropy(self, password):
        """
        Calculate password entropy in bits.
        Entropy = log2(character_pool_size ^ password_length)
        Higher entropy = stronger password
        """
        pool_size = 0
        
        # Determine which character sets are used
        if re.search(r'[a-z]', password):
            pool_size += len(self.charsets['lowercase'])
        if re.search(r'[A-Z]', password):
            pool_size += len(self.charsets['uppercase'])
        if re.search(r'\d', password):
            pool_size += len(self.charsets['digits'])
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += len(self.charsets['special'])
        
        if pool_size == 0:
            return 0
            
        entropy = len(password) * (pool_size.bit_length() - 1)
        return entropy
    
    def check_length(self, password):
        """Check password length security"""
        length = len(password)
        if length < 8:
            return "❌ Too short (minimum 8 characters)", 0
        elif length < 12:
            return "⚠️ Acceptable (8-11 characters)", 1
        elif length < 16:
            return "✅ Good (12-15 characters)", 2
        else:
            return "🌟🌟 Excellent (16+ characters)", 3
    
    def check_character_variety(self, password):
        """Evaluate character type diversity"""
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        
        types_used = sum([has_lower, has_upper, has_digit, has_special])
        
        if types_used == 1:
            return "❌ Poor - Only one character type", 0
        elif types_used == 2:
            return "⚠️ Weak - Only two character types", 1
        elif types_used == 3:
            return "✅ Good - Three character types", 2
        else:
            return "🌟🌟 Excellent - All four character types", 3
    
    def check_common_patterns(self, password):
        """Check for common patterns and sequences"""
        issues = []
        score_penalty = 0
        
        # Check against common passwords
        if password.lower() in self.common_passwords:
            issues.append("Common/known password detected")
            score_penalty += 2
        
        # Check for sequential characters
        sequences = ['123', '234', '345', '456', '567', '678', '789',
                    'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi',
                    'qwe', 'wer', 'ert', 'rty', 'tyu', 'yui', 'uia',
                    'asd', 'sdf', 'dfg', 'fgh', 'ghj', 'hjk', 'jkl',
                    'zxc', 'xcv', 'cvb', 'vbn', 'bnm']
        
        for seq in sequences:
            if seq in password.lower():
                issues.append(f"Contains sequence: '{seq}'")
                score_penalty += 1
                break
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            issues.append("Contains repeated characters (e.g., 'aaa')")
            score_penalty += 1
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                issues.append("Contains keyboard pattern")
                score_penalty += 1
                break
        
        # Check for date patterns (year)
        if re.search(r'(19|20)\d{2}', password):
            issues.append("Contains a year (e.g., 1990-2024)")
            score_penalty += 1
        
        if issues:
            return issues, score_penalty
        return ["✅ No common patterns detected"], 0
    
    def check_repeated_characters_safe(self, password):
        """Check for repeated characters with constant-time approach"""
        # This is a simplified demonstration of timing-attack awareness
        # In real implementation, use constant-time comparison for sensitive ops
        if re.search(r'(.)\1{3,}', password):
            return "⚠️ Contains 4+ repeated characters in a row"
        return "✅ No excessive repetition"
    
    def constant_time_compare(self, str1, str2):
        """
        Constant-time comparison to prevent timing attacks.
        This is crucial for comparing sensitive strings like passwords.
        """
        return hmac.compare_digest(str1, str2)
    
    def check_password_against_previous(self, current, previous):
        """Compare with previous password using constant-time"""
        if self.constant_time_compare(current, previous):
            return "❌ Password is identical to previous password"
        return "✅ Different from previous password"
    
    def evaluate_strength(self, password, previous_password=None):
        """
        Main evaluation function that combines all checks
        Returns comprehensive strength report
        """
        print("\n" + "="*60)
        print("PASSWORD STRENGTH ANALYSIS REPORT")
        print("="*60)
        print(f"Password: {'*' * len(password)}")
        print(f"Length: {len(password)} characters")
        print("-"*60)
        
        total_score = 0
        max_score = 12
        
        # 1. Length Check
        length_msg, length_score = self.check_length(password)
        print(f"\n📏 LENGTH: {length_msg}")
        total_score += length_score
        
        # 2. Character Variety
        variety_msg, variety_score = self.check_character_variety(password)
        print(f"🎨 CHARACTER VARIETY: {variety_msg}")
        total_score += variety_score
        
        # 3. Common Patterns
        pattern_issues, pattern_penalty = self.check_common_patterns(password)
        print(f"\n⚠️ PATTERN ANALYSIS:")
        for issue in pattern_issues:
            print(f"   • {issue}")
        total_score -= pattern_penalty
        
        # 4. Entropy Calculation
        entropy = self.calculate_entropy(password)
        entropy_rating = "Low" if entropy < 30 else "Medium" if entropy < 50 else "High" if entropy < 70 else "Very High"
        print(f"\n🔐 ENTROPY: {entropy:.1f} bits ({entropy_rating})")
        
        # 5. Final Strength Rating
        normalized_score = max(0, min(10, (total_score / max_score) * 10))
        
        print("\n" + "-"*60)
        print("FINAL ASSESSMENT:")
        
        if normalized_score >= 8:
            strength = "🌟🌟🌟 VERY STRONG"
            color = "\033[92m"  # Green
            advice = "Excellent password! Keep using strong practices."
        elif normalized_score >= 6:
            strength = "🌟🌟 MODERATE"
            color = "\033[93m"  # Yellow
            advice = "Good, but could be stronger. Add more variety and length."
        elif normalized_score >= 4:
            strength = "⭐ WEAK"
            color = "\033[91m"  # Red
            advice = "Weak password. Increase length and use multiple character types."
        else:
            strength = "❌ VERY WEAK"
            color = "\033[91m"  # Red
            advice = "Extremely weak! Avoid common patterns and use stronger combinations."
        
        print(f"{color}{strength}\033[0m")
        print(f"Score: {normalized_score:.1f}/10")
        print(f"\n💡 RECOMMENDATION: {advice}")
        
        # Check against previous password if provided
        if previous_password:
            comparison = self.check_password_against_previous(password, previous_password)
            print(f"\n🔄 PREVIOUS PASSWORD: {comparison}")
        
        print("="*60)
        
        return {
            'strength': strength,
            'score': normalized_score,
            'entropy': entropy,
            'length': len(password),
            'recommendation': advice
        }


class SecurePasswordInput:
    """
    Handles secure password input with masking and timing-attack awareness
    """
    
    @staticmethod
    def get_password(prompt="Enter password: "):
        """
        Simulate secure password input (getpass would be used in production)
        """
        import getpass
        return getpass.getpass(prompt)
    
    @staticmethod
    def simulate_timing_attack_demo():
        """
        Demonstration of why constant-time comparison is important
        """
        print("\n" + "="*60)
        print("TIMING ATTACK DEMONSTRATION")
        print("="*60)
        print("This shows why constant-time comparison is critical!")
        
        correct_password = "secret123"
        wrong_password = "secrets99"
        
        print(f"\nUsing regular comparison (vulnerable):")
        
        # Regular comparison - vulnerable to timing attacks
        start = time.perf_counter()
        result = (correct_password == wrong_password)
        end = time.perf_counter()
        print(f"  Comparison time: {(end-start)*1000000:.2f} microseconds")
        
        print(f"\nUsing constant-time comparison (secure):")
        
        # Constant-time comparison - immune to timing attacks
        start = time.perf_counter()
        result = hmac.compare_digest(correct_password, wrong_password)
        end = time.perf_counter()
        print(f"  Comparison time: {(end-start)*1000000:.2f} microseconds")
        
        print("\n✅ Constant-time comparison always takes the same amount of time,")
        print("   preventing attackers from guessing based on response timing!")


def main():
    """
    Main program loop for Password Strength Checker
    """
    print("\n" + "="*60)
    print("🔒 DECODELABS PASSWORD STRENGTH CHECKER 🔒")
    print("Cybersecurity Project 1 - Defensive Phase")
    print("="*60)
    print("\nThis tool evaluates password security using:")
    print("• Length analysis")
    print("• Character variety scoring")
    print("• Common pattern detection")
    print("• Entropy calculation")
    print("• Timing-attack awareness")
    
    checker = PasswordStrengthChecker()
    previous_password = None
    
    while True:
        print("\n" + "-"*60)
        print("OPTIONS:")
        print("1. Check a new password")
        print("2. Demo: Show how timing attacks work")
        print("3. Exit")
        print("-"*60)
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == '1':
            # Get password securely
            password = SecurePasswordInput.get_password("\nEnter password to check: ")
            
            if not password:
                print("❌ Password cannot be empty!")
                continue
            
            confirm = SecurePasswordInput.get_password("Confirm password: ")
            
            if password != confirm:
                print("❌ Passwords do not match!")
                continue
            
            # Evaluate password strength
            result = checker.evaluate_strength(password, previous_password)
            
            # Ask if this should be saved as previous password
            if result['score'] >= 6:
                save = input("\nSave as previous password for future comparison? (y/n): ").lower()
                if save == 'y':
                    previous_password = password
                    print("✅ Password saved for future reference")
        
        elif choice == '2':
            SecurePasswordInput.simulate_timing_attack_demo()
        
        elif choice == '3':
            print("\n👋 Thank you for using DecodeLabs Password Strength Checker!")
            print("Remember: Strong passwords are your first line of defense!")
            break
        
        else:
            print("❌ Invalid choice. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()