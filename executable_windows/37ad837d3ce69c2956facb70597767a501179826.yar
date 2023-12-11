rule INDICATOR_SUSPICOIUS_RTF_EncodedURL
{
	meta:
		author = "ditekSHen"
		description = "Detects executables calling ClearMyTracksByProcess"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\u-65431?\\u-65419?\\u-65419?\\u-65423?\\u-" ascii wide
		$s2 = "\\u-65432?\\u-65420?\\u-65420?\\u-65424?\\u-" ascii wide
		$s3 = "\\u-65433?\\u-65430?\\u-65427?\\u-65434?\\u-" ascii wide
		$s4 = "\\u-65434?\\u-65431?\\u-65428?\\u-65435?\\u-" ascii wide

	condition:
		uint32(0)==0x74725c7b and any of them
}
