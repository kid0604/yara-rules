rule CN_Honker_exp_ms11011
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11011.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5ad7a4962acbb6b0e3b73d77385eb91feb88b386"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\i386\\Hello.pdb" ascii
		$s1 = "OS not supported." fullword ascii
		$s2 = ".Rich5" fullword ascii
		$s3 = "Not supported." fullword wide
		$s5 = "cmd.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
