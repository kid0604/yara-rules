import "pe"

rule Greenbug_Malware_1
{
	meta:
		description = "Detects Malware from Greenbug Incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/urp4CD"
		date = "2017-01-25"
		hash1 = "dab460a0b73e79299fbff2fa301420c1d97a36da7426acc0e903c70495db2b76"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "vailablez" fullword ascii
		$s2 = "Sfouglr" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and all of them )
}
