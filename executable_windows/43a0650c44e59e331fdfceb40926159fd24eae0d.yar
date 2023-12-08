import "pe"

rule CN_disclosed_20180208_System3
{
	meta:
		description = "Detects malware from disclosed CN malware set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyberintproject/status/961714165550342146"
		date = "2018-02-08"
		hash1 = "73fa84cff51d384c2d22d9e53fc5d42cb642172447b07e796c81dd403fb010c2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "WmiPrvSE.exe" fullword wide
		$s1 = "C:\\Users\\sgl\\AppData\\Local\\" ascii
		$s2 = "Temporary Projects\\WmiPrvSE\\" ascii
		$s3 = "$15a32a5d-4906-458a-8f57-402311afc1c1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and $a1 and 1 of ($s*)
}
