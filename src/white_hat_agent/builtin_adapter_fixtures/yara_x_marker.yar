rule wha_native_marker : conformance
{
    meta:
        purpose = "White Hat Agent typed YARA-X conformance"

    strings:
        $marker = "WHA_NATIVE_CODE_MAP_MARKER" ascii

    condition:
        $marker
}
