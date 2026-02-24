"""Top-level package for Transparent Research Object utils."""

from enum import Enum, EnumMeta

__author__ = """Kacper Kowalik"""
__email__ = "xarthisius.kk@gmail.com"
__version__ = "0.2.1"


class MetaEnum(EnumMeta):
    @property
    def values(cls):
        return [member.value for member in cls]

    def __contains__(cls, item):
        return item in cls.values

    def translate(cls, source_member):
        try:
            return cls[source_member.name]
        except (KeyError, AttributeError):
            raise ValueError(
                f"No corresponding member in {cls.__name__} for {source_member}"
            )


class TROVTypeEnum(Enum, metaclass=MetaEnum):
    pass


class TROVCapability(TROVTypeEnum):
    RECORD_NETWORK = "trov:CanRecordInternetAccess"
    NET_ISOLATION = "trov:CanProvideInternetIsolation"
    # NET_ISOLATION = "trov:CanEnforceInternetIsolation"
    ENV_ISOLATION = "trov:CanIsolateEnvironment"
    NON_INTERACTIVE = "trov:CanPreventAuthorIntervention"
    # NON_INTERACTIVE = "trov:CanPreventUserInteractionDuringRun"
    EXCLUDE_INPUT = "trov:CanExcludeInputs"
    EXCLUDE_OUTPUT = "trov:CanExcludeOutputs"
    ALL_DATA_INCLUDED = "trov:CanEnsureInputDataIncludedInTROPackage"
    REQUIRE_INPUT_DATA = "trov:CanRequireInputDataExistsBeforeRun"
    REQUIRE_LOCAL_DATA = "trov:CanRequireInputDataLocalBeforeRun"
    DATA_PERSIST = "trov:CanEnsureInputDataPersistsAfterRun"
    OUTPUT_INCLUDED = "trov:CanEnsureOutputDataIncludedInTROPackage"
    CODE_INCLUDED = "trov:CanEnsureCodeIncludedInTROPackage"
    SOFTWARE_RECORD = "trov:CanRecordSoftwareEnvironment"
    NET_ACCESS = "trov:CanDetectInternetAccess"
    MACHINE_ENFORCEMENT = "trov:CanEnforceCapabilitiesTechnically"


class TRPAttribute(TROVTypeEnum):
    RECORD_NETWORK = "trov:InternetAccessRecording"
    NET_ISOLATION = "trov:InternetIsolation"
    ENV_ISOLATION = "trov:EnvironmentIsolation"
    NON_INTERACTIVE = "trov:NonInteractiveExecution"
    EXCLUDE_INPUT = "trov:InputsExcluded"
    EXCLUDE_OUTPUT = "trov:OutputsExcluded"
    ALL_DATA_INCLUDED = "trov:AllInputDataIncludedInTROPackage"
    REQUIRE_INPUT_DATA = "trov:RequiredInputDataExistsBeforeRun"
    REQUIRE_LOCAL_DATA = "trov:RequiredInputDataLocalBeforeRun"
    DATA_PERSIST = "trov:InputDataPersistedAfterRun"
    OUTPUT_INCLUDED = "trov:OutputDataIncludedInTROPackage"
    CODE_INCLUDED = "trov:CodeIncludedInTROPackage"
    SOFTWARE_RECORD = "trov:SoftwareEnvironmentRecorded"
    NET_ACCESS = "trov:InternetAccessDetection"
    MACHINE_ENFORCEMENT = "trov:CapabilitiesTechnicallyEnforced"
