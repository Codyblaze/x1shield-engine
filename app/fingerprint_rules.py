from app.schemas import AnalyzeRequest, RuleResult

class PlatformMismatchRule:
    def __init__(self):
        # map lazy bot UA strings to expected hardware
        self.expected_platforms = {
            "windows": ["win32", "win64"],
            "mac": ["macintel", "macintosh"],
            "linux": ["linux x86_64", "linux i686"],
            "android": ["android", "linux arm"],
            "iphone": ["iphone"],
            "ipad": ["ipad"]
        }

    def evaluate(self, request: AnalyzeRequest) -> RuleResult:
        # base assumption: human until proven otherwise
        result = RuleResult(
            name="PlatformMismatch",
            tripped=False,
            score=0.0,
            detail=None
        )

        browser = request.fingerprint.browser_data
        if not browser or not browser.user_agent or not browser.platform:
            return result
            
        ua = browser.user_agent.lower()
        hw_platform = browser.platform.lower()

        claimed_os = next((os for os in self.expected_platforms if os in ua), None)
                
        if claimed_os:
            valid_hw = self.expected_platforms[claimed_os]
            # trigger if puppeteer injected a Windows UA but is running on a linux container
            if not any(v in hw_platform for v in valid_hw):
                result.tripped = True
                result.score = 60.0
                result.detail = f"UA claims {claimed_os} but platform is {hw_platform}"

        return result