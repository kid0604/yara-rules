rule Empire_ReflectivePick_x64_orig
{
	meta:
		description = "Detects Empire component - file ReflectivePick_x64_orig.dll"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "a8c1b108a67e7fc09f81bd160c3bafb526caf3dbbaf008efb9a96f4151756ff2"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\PowerShellRunner.pdb" fullword ascii
		$s2 = "PowerShellRunner.dll" fullword wide
		$s3 = "ReflectivePick_x64.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 1 of them ) or all of them
}
