rule INDICATOR_KB_ID_BazarLoader
{
	meta:
		author = "ditekShen"
		description = "Detects Bazar executables with specific email addresses found in the code signing certificate"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "skarabeyllc@gmail.com" ascii wide nocase
		$s2 = "admin@intell-it.ru" ascii wide nocase
		$s3 = "support@pro-kon.ru" ascii wide

	condition:
		uint16(0)==0x5a4d and any of them
}
