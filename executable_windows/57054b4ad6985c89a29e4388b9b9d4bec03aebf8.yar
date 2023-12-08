rule Dubnium_Sample_3
{
	meta:
		description = "Detects sample mentioned in the Dubnium Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/AW9Cuu"
		date = "2016-06-10"
		hash1 = "caefcdf2b4e5a928cdf9360b70960337f751ec4a5ab8c0b75851fc9a1ab507a8"
		hash2 = "e0362d319a8d0e13eda782a0d8da960dd96043e6cc3500faeae521d1747576e5"
		hash3 = "a77d1c452291a6f2f6ed89a4bac88dd03d38acde709b0061efd9f50e6d9f3827"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "copy /y \"%s\" \"%s\" " fullword ascii
		$x2 = "del /f \"%s\" " fullword ascii
		$s1 = "del /f /ah \"%s\" " fullword ascii
		$s2 = "if exist \"%s\" goto Rept " fullword ascii
		$s3 = "\\*.*.lnk" ascii
		$s4 = "Dropped" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and 5 of them
}
