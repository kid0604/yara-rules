rule CN_Honker_ManualInjection
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ManualInjection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e83d427f44783088a84e9c231c6816c214434526"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://127.0.0.1/cookie.asp?fuck=" fullword ascii
		$s16 = "http://Www.cnhuker.com | http://www.0855.tv" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and all of them
}
