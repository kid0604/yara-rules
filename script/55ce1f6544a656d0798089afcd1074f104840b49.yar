rule webshell_webshells_new_Asp
{
	meta:
		description = "Web shells - generated from file Asp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "32c87744ea404d0ea0debd55915010b7"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
		$s2 = "Function MorfiCoder(Code)" fullword
		$s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword

	condition:
		1 of them
}
