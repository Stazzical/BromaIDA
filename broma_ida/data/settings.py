from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class SettingDefinition:
    key: str            # DataManager shelf key
    control_name: str   # settings form control name key
    default: Any
    label: str          # settings form option name
    tooltip: str = ""   # settings form tooltip that shows when you hover over the option


@dataclass(frozen=True, slots=True)
class SettingsGroup:
    title: str
    control_name: str   # form ChkGroupControl name key
    settings: tuple[SettingDefinition, ...]


# this dynamically populates SettingsForm
SETTINGS_GROUPS: tuple[SettingsGroup, ...] = (
    SettingsGroup(
        title="General Settings",
        control_name="cGeneralSettingsGroup",
        settings=(
            # TODO: in the future, we might have support for applying
            # Broma 'docs' attribute, update relative to future changes
            SettingDefinition(
                "always_overwrite_merge_information",
                "rAlwaysOverwriteMergeInformation",
                False,
                "Always Overwrite Function Comments with Merge Information",
                "Do not prompt when there is a mismatch in merge information "
                "stored in function comments.",
            ),
            SettingDefinition(
                "always_overwrite_idb",
                "rAlwaysOverwriteIDB",
                False,
                "Always Overwrite IDB",
                "Do not prompt when there is a mismatch between IDB and "
                "the Broma files.\nBromaIDA will silently overwrite the IDB.",
            ),
            SettingDefinition(
                "disable_input_hash_check",
                "rDisableInputHashCheck",
                False,
                "Disable Input File Hashes Check",
                "Skips the input files hash check that determines if types should "
                "be imported.\nThe Broma files' hashes are saved "
                "upon a successful import relative to the current\n"
                "binary's target platform, and compared to any previously "
                "saved file hashes;\nif identical, BromaIDA will "
                "skip importing types.",
            ),
            SettingDefinition(
                "export_return_types",
                "rExportReturnTypes",
                False,
                "Export Return Types",
                "If return types should be exported.\nIf enabled, only "
                "types that aren't 'TodoReturn' are exported.\nBecause of "
                "that, it is only recommended to enable this if types are "
                "already imported beforehand.",
            ),
            SettingDefinition(
                "export_args_names",
                "rExportFunctionArgumentsNames",
                False,
                "Export Function Argument Names",
                "If function argument names should be exported.\nIf "
                "enabled, only names that don't match \"a[0-9]+\" and "
                "\"p[0-9]+\" are exported.",
            ),
            SettingDefinition(
                "ignore_unmarked_functions",
                "rIgnoreUnmarkedFunctions",
                True,
                "Ignore Unmarked Functions",
                "Ignore addresses that IDA has not marked as a function.\n"
                "If enabled, BromaIDA will automatically skip applying the "
                "binding and will not mark the address as a function.",
            ),
            SettingDefinition(
                "debug_info",
                "rEnableDebugInfo",
                False,
                "Enable Debug Info",
                "Enable debug information logging "
                "when importing Broma files.",
            ),
        ),
    ),
    SettingsGroup(
        title="Type Import Settings",
        control_name="cImportTypesSettingsGroup",
        settings=(
            SettingDefinition(
                "import_types",
                "rImportTypes",
                True,
                "Import Types",
                "Enables importing of the defined classes from the input "
                "Broma files, alongside some pre-made headers for "
                "Cocos2d-x and other components.\nWill yield VTables and "
                "members for IDA to digest and resolve in psuedocodes.",
            ),
            SettingDefinition(
                "set_default_parser_args",
                "rSetDefaultParserArguments",
                True,
                "Set Default Parser Arguments",
                "Sets IDAClang's parser arguments to automatically suit "
                "the current binary's platform.",
            ),
            SettingDefinition(
                "ignore_mismatched_structs",
                "rIgnoreMismatchedStructs",
                False,
                "Ignore Mismatched Structs",
                "Disable checking if BromaIDA's structs match from a "
                "previous import. (NOT RECOMMENDED)\nIf enabled, no "
                "warning will be issued for importing types over "
                "previously imported types.\nOverwriting types may "
                "potentially silently fail.",
            ),
        ),
    ),
)

ALL_SETTINGS: tuple[SettingDefinition, ...] = tuple(
    s for g in SETTINGS_GROUPS for s in g.settings
)
SETTINGS_BY_KEY: dict[str, SettingDefinition] = {
    s.key: s for s in ALL_SETTINGS
}
