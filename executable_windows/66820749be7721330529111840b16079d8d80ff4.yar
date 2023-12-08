rule Winnti_NlaifSvc
{
	meta:
		description = "Winnti sample - file NlaifSvc.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/VbvJtL"
		date = "2017-01-25"
		hash1 = "964f9bfd52b5a93179b90d21705cd0c31461f54d51c56d558806fe0efff264e5"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "cracked by ximo" ascii
		$s1 = "Yqrfpk" fullword ascii
		$s2 = "IVVTOC" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 2 of them )) or (3 of them )
}
