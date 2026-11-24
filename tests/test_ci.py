import unittest
from sentwall.ci import generate_github_workflow, generate_gitlab_ci


class TestCI(unittest.TestCase):
    def test_github_workflow(self):
        wf = generate_github_workflow()
        self.assertIn("Sentwall Security Gate", wf)
        self.assertIn("upload-sarif", wf)

    def test_gitlab_ci(self):
        ci = generate_gitlab_ci()
        self.assertIn("sentwall-security-scan", ci)
        self.assertIn("reports/*.sarif", ci)


if __name__ == "__main__":
    unittest.main()
