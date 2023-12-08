rule Malware_QA_tls
{
	meta:
		description = "VT Research QA uploaded malware - file tls.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "f06d1f2bee2eb6590afbfa7f011ceba9bd91ba31cdc721bc728e13b547ac9370"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\funoverip\\ultimate-payload-template1\\" ascii
		$s2 = "ULTIMATEPAYLOADTEMPLATE1" fullword wide
		$s3 = "ultimate-payload-template1" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of them ) or ( all of them )
}
