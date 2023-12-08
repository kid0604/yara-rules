import "pe"

rule APT_Thrip_Sample_Jun18_7
{
	meta:
		description = "Detects sample found in Thrip report by Symantec "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.symantec.com/blogs/threat-intelligence/thrip-hits-satellite-telecoms-defense-targets "
		date = "2018-06-21"
		hash1 = "6b714dc1c7e58589374200d2c7f3d820798473faeb26855e53101b8f3c701e3f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\runme.exe" ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and 1 of them
}
