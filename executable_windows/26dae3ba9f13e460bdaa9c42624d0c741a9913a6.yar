import "pe"

rule APT_Thrip_Sample_Jun18_6
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "44f58496578e55623713c4290abb256d03103e78e99939daeec059776bd79ee2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Windows\\system32\\Instell.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 1 of them
}
