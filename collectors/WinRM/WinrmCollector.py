from collectors.WinRM.WinrmBaseCollector import WinrmBaseCollector


class WinrmCollector(WinrmBaseCollector):
    @property
    def port(self) -> int:
        return 5985

    @property
    def scheme(self) -> str:
        return "http"

    @property
    def name(self) -> str:
        return "WinRM"


