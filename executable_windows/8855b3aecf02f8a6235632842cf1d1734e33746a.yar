rule Emotets
{
	meta:
		author = "pekeinfo"
		date = "2017-10-18"
		description = "Emotets"
		os = "windows"
		filetype = "executable"

	strings:
		$mz = { 4d 5a }
		$cmovnz = { 0f 45 fb 0f 45 de }
		$mov_esp_0 = { C7 04 24 00 00 00 00 89 44 24 0? }
		$_eax = { 89 E? 8D ?? 24 ?? 89 ?? FF D0 83 EC 04 }

	condition:
		($mz at 0 and $_eax in (0x2854..0x4000)) and ($cmovnz or $mov_esp_0)
}
