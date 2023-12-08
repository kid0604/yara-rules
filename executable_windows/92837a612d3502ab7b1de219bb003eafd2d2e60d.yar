rule INDICATOR_KB_ID_Amadey
{
	meta:
		author = "ditekShen"
		description = "Detects Amadey executables with specific email addresses found in the code signing certificate"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "tochka.director@gmail.com" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and any of them
}
