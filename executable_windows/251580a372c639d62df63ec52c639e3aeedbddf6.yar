rule SUSP_Microsoft_Copyright_String_Anomaly_2
{
	meta:
		description = "Detects Floxif Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2018-05-11"
		score = 60
		hash1 = "de055a89de246e629a8694bde18af2b1605e4b9b493c7e4aef669dd67acf5085"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Microsoft(C) Windows(C) Operating System" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 1 of them
}
