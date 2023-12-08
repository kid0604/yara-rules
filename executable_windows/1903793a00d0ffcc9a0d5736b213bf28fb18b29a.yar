rule CN_Honker_Injection_alt_1
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Injection.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3484ed16e6f9e0d603cbc5cb44e46b8b7e775d35"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://127.0.0.1/6kbbs/bank.asp" fullword ascii
		$s7 = "jmPost.asp" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <220KB and all of them
}
