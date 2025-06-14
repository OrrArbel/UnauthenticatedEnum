from collectors.WinRM.WinrmBaseCollector import WinrmBaseCollector


class WinrmsCollector(WinrmBaseCollector):
    @property
    def port(self) -> int:
        return 5986

    @property
    def scheme(self) -> str:
        return "https"

    @property
    def name(self) -> str:
        return "WinRMS"
