from app.schemas import Fingerprint, RuleResult
from app.rules import HeuristicRule

class PlatformMismatchRule(HeuristicRule):
    name = "platform_mismatch"
    weight = 1.0

    def __init__(self):
        self.expected_platforms = {
            "windows": ["win32", "win64"],
            "mac": ["macintel", "macintosh"],
            "linux": ["linux x86_64", "linux i686"],
            "android": ["android", "linux arm"],
            "iphone": ["iphone"],
            "ipad": ["ipad"]
        }

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        result = RuleResult(name=self.name, tripped=False, score=0.0, detail=None)

        browser = fingerprint.browser_data
        if not browser or not browser.user_agent or not browser.platform:
            return result
            
        ua = browser.user_agent.lower()
        hw_platform = browser.platform.lower()

        claimed_os = next((os for os in self.expected_platforms if os in ua), None)
                
        if claimed_os:
            valid_hw = self.expected_platforms[claimed_os]
            if not any(v in hw_platform for v in valid_hw):
                result.tripped = True
                result.score = 60.0
                result.detail = f"UA claims {claimed_os} but platform is {hw_platform}"

        return result


class FontEnumerationRule(HeuristicRule):
    name = "font_enumeration_anomaly"
    weight = 1.0

    def __init__(self, min_human_fonts: int = 20):
        self.min_fonts = min_human_fonts

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        result = RuleResult(name=self.name, tripped=False, score=0.0, detail=None)

        browser = fingerprint.browser_data
        if not browser or browser.fonts is None:
            return result
            
        font_count = len(browser.fonts)
        
        if 0 < font_count < self.min_fonts:
            result.tripped = True
            result.score = 45.0
            result.detail = f"Suspiciously low font count ({font_count}). Likely a headless instance."
        elif font_count == 0:
            result.tripped = True
            result.score = 25.0
            result.detail = "Font fingerprinting completely blocked or empty."

        return result
 class WebGLSpoofingRule(HeuristicRule):
    name = "webgl_hardware_spoofing"
    weight = 1.5

    def __init__(self):
        
        self.software_renderers = ["swiftshader", "llvmpipe", "google", "mesa offscreen"]
       
        self.apple_gpus = ["apple m1", "apple m2", "apple m3", "apple gpu"]

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        result = RuleResult(name=self.name, tripped=False, score=0.0, detail=None)
        
        browser = fingerprint.browser_data
        if not browser or not browser.webgl_renderer:
            return result

        renderer = browser.webgl_renderer.lower()
        platform = (browser.platform or "").lower()

        
        if any(sw in renderer for sw in self.software_renderers):
            result.tripped = True
            result.score = 75.0
            result.detail = f"Software renderer detected ({renderer}). High probability of headless VM."
            return result

        
        is_apple_gpu = any(mac_gpu in renderer for mac_gpu in self.apple_gpus)
        is_mac_platform = "mac" in platform

        if is_apple_gpu and not is_mac_platform:
            result.tripped = True
            result.score = 85.0
            result.detail = f"Impossible hardware mismatch: Apple GPU claimed on {platform} platform."
            return result

        return result   