rule CN_Honker_GroupPolicyRemover
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GroupPolicyRemover.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7475d694e189b35899a2baa462957ac3687513e5"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "GP_killer.EXE" fullword wide
		$s1 = "GP_killer Microsoft " fullword wide
		$s2 = "SHDeleteKeyA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and all of them
}
