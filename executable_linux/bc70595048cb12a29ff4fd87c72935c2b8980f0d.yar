rule BlackEnergy_BackdoorPass_DropBear_SSH
{
	meta:
		description = "Detects the password of the backdoored DropBear SSH Server - BlackEnergy"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://feedproxy.google.com/~r/eset/blog/~3/BXJbnGSvEFc/"
		date = "2016-01-03"
		hash = "0969daac4adc84ab7b50d4f9ffb16c4e1a07c6dbfc968bd6649497c794a161cd"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "passDs5Bu9Te7" fullword ascii

	condition:
		uint16(0)==0x5a4d and $s1
}
