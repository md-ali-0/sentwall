import unittest
from vulnscope.checks.secrets import shannon_entropy, SECRET_RULES
from vulnscope.checks.waf import WAF_SIGNATURES


class TestNewChecks(unittest.TestCase):
    def test_shannon_entropy(self):
        low_ent = shannon_entropy("aaaaaaaaaaaa")
        high_ent = shannon_entropy("8f4d9b2e1a3c7f0d5a6b")
        self.assertLess(low_ent, 1.0)
        self.assertGreater(high_ent, 3.0)

    def test_secret_rules(self):
        import re
        sample_openai = "sk-proj-abc123def456ghi789jkl012mno345pqr"
        openai_rule = next(r for r in SECRET_RULES if "OpenAI" in r[0])
        self.assertTrue(re.search(openai_rule[1], sample_openai))

        sample_aws = "AKIA1234567890ABCDEF"
        aws_rule = next(r for r in SECRET_RULES if "AWS Access Key ID" in r[0])
        self.assertTrue(re.search(aws_rule[1], sample_aws))

    def test_waf_signatures(self):
        self.assertTrue(any("Cloudflare" in s[0] for s in WAF_SIGNATURES))
        self.assertTrue(any("AWS WAF" in s[0] for s in WAF_SIGNATURES))


if __name__ == "__main__":
    unittest.main()
