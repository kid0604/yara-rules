rule Empire_ReflectivePick_x64_orig_alt_1
{
	meta:
		description = "Detects Empire component - file ReflectivePick_x64_orig.dll"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		modified = "2022-12-21"
		hash1 = "a8c1b108a67e7fc09f81bd160c3bafb526caf3dbbaf008efb9a96f4151756ff2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "\\PowerShellRunner.pdb" ascii
		$a2 = "PowerShellRunner.dll" fullword wide
		$s1 = "ReflectivePick" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and 1 of ($a*) and $s1
}
