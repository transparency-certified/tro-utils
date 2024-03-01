"""Top-level package for Transparent Research Object utils."""

__author__ = """Kacper Kowalik"""
__email__ = "xarthisius.kk@gmail.com"
__version__ = "0.1.0"


class TROVCapability:
    RECORD_NETWORK = "trov:CanRecordInternetAccess"
    ISOLATION = "trov:CanProvideInternetIsolation"


class TRPAttribute:
    RECORD_NETWORK = "trov:InternetAccessRecording"
    ISOLATION = "trov:InternetIsolation"


caps_mapping = {
    TRPAttribute.RECORD_NETWORK: TROVCapability.RECORD_NETWORK,
    TRPAttribute.ISOLATION: TROVCapability.ISOLATION,
}
