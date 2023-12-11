rule Sofacy_Malware_AZZY_Backdoor_1
{
	meta:
		description = "AZZY Backdoor - Sample 1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/research/72924/sofacy-apt-hits-high-profile-targets-with-updated-toolset/"
		date = "2015-12-04"
		hash = "a9dc96d45702538c2086a749ba2fb467ba8d8b603e513bdef62a024dfeb124cb"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "advstorshell.dll" fullword wide
		$s1 = "advshellstore.dll" fullword ascii
		$s2 = "Windows Advanced Storage Shell Extension DLL" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <150KB and 2 of them
}
