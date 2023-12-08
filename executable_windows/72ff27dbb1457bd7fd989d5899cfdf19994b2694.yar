import "pe"

rule APT_FallChill_RC4_Keys
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Detects FallChill RC4 keys"
		reference = "https://securelist.com/operation-applejeus/87553/"
		date = "2018-08-21"
		os = "windows"
		filetype = "executable"

	strings:
		$cod0 = { c7 ?? ?? da e1 61 ff
                c7 ?? ?? 0c 27 95 87
                c7 ?? ?? 17 57 a4 d6
                c7 ?? ?? ea e3 82 2b }

	condition:
		uint16(0)==0x5a4d and 1 of them
}
