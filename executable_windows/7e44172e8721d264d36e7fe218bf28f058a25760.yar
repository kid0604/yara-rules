rule SUSP_SFX_cmd
{
	meta:
		description = "Detects suspicious SFX as used by Gamaredon group"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-09-27"
		hash1 = "965129e5d0c439df97624347534bc24168935e7a71b9ff950c86faae3baec403"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = /RunProgram=\"hidcon:[a-zA-Z0-9]{1,16}.cmd/ fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 1 of them
}
