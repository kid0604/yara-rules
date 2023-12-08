rule IsmDoor_Jul17_A2
{
	meta:
		description = "Detects IsmDoor Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/Voulnet/status/892104753295110145"
		date = "2017-08-01"
		hash1 = "be72c89efef5e59c4f815d2fce0da5a6fac8c90b86ee0e424868d4ae5e550a59"
		hash2 = "ea1be14eb474c9f70e498c764aaafc8b34173c80cac9a8b89156e9390bd87ba8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "powershell -exec bypass -file \"" fullword ascii
		$s2 = "PAQlFcaWUaFkVICEx2CkNCUUpGcA" ascii
		$s3 = "\\Documents" ascii
		$s4 = "\\Libraries" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them )
}
