rule CN_Honker__builder_shift_SkinH
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files builder.exe, shift.exe, SkinH.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "6b5a84cdc3d27c435d49de3f68872d015a5aadfc"
		hash1 = "ee127c1ea1e3b5bf3d2f8754fabf9d1101ed0ee0"
		hash2 = "d593f03ae06e54b653c7850c872c0eed459b301f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "lipboard" fullword ascii
		$s2 = "uxthem" fullword ascii
		$s3 = "ENIGMA" fullword ascii
		$s4 = "UtilW0ndow" fullword ascii
		$s5 = "prog3am" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <6075KB and all of them
}
