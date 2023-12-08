rule Fireball_archer
{
	meta:
		description = "Detects Fireball malware - file archer.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		modified = "2022-12-21"
		hash1 = "9b4971349ae85aa09c0a69852ed3e626c954954a3927b3d1b6646f139b930022"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\archer_lyl\\Release\\Archer_Input.pdb" ascii
		$s1 = "Archer_Input.dll" fullword ascii
		$s2 = "InstallArcherSvc" fullword ascii
		$s3 = "%s_%08X" fullword wide
		$s4 = "d\\\\.\\PhysicalDrive%d" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and ($x1 or 3 of them )
}
