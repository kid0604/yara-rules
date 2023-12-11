import "pe"

rule APT_Thrip_Sample_Jun18_14
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "67dd44a8fbf6de94c4589cf08aa5757b785b26e49e29488e9748189e13d90fb3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%SystemRoot%\\System32\\svchost.exe -k " fullword ascii
		$s2 = "spdirs.dll" fullword ascii
		$s3 = "Provides storm installation services such as Publish, and Remove." fullword ascii
		$s4 = "RegSetValueEx(Svchost\\netsvcs)" fullword ascii
		$s5 = "Load %s Error" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ((pe.exports("InstallA") and pe.exports("InstallB") and pe.exports("InstallC")) or all of them )
}
