import "pe"

rule APT_Thrip_Sample_Jun18_2
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "1fc9f7065856cd8dc99b6f46cf0953adf90e2c42a3b65374bf7b50274fb200cc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" fullword ascii
		$s2 = "ProbeScriptFint" fullword wide
		$s3 = "C:\\WINDOWS\\system32\\cmd.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
