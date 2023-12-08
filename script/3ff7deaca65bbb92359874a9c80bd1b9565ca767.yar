rule Armitage_MeterpreterSession_Strings
{
	meta:
		description = "Detects Armitage component"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-12-24"
		hash1 = "b258b2f12f57ed05d8eafd29e9ecc126ae301ead9944a616b87c240bf1e71f9a"
		hash2 = "144cb6b1cf52e60f16b45ddf1633132c75de393c2705773b9f67fce334a3c8b8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "session.meterpreter_read" fullword ascii
		$s2 = "sniffer_dump" fullword ascii
		$s3 = "keyscan_dump" fullword ascii
		$s4 = "MeterpreterSession.java" fullword ascii

	condition:
		filesize <30KB and 1 of them
}
