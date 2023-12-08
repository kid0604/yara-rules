import "pe"

rule APT_Thrip_Sample_Jun18_5
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "32889639a27961497d53176765b3addf9fff27f1c8cc41634a365085d6d55920"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "c:\\windows\\USBEvent.exe" fullword ascii
		$s5 = "c:\\windows\\spdir.dat" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and all of them
}
