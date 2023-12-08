import "pe"

rule APT_Thrip_Sample_Jun18_3
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "0d2abdcaad99e102fdf6574b3dc90f17cb9d060c20e6ac4ff378875d3b91a840"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Windows\\SysNative\\cmd.exe" fullword ascii
		$s2 = "C:\\Windows\\SysNative\\sysprep\\cryptbase.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
