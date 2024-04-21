rule gozi_17386_alsoOne_bat
{
	meta:
		description = "Gozi - file alsoOne.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "c03f5e2bc4f2307f6ee68675d2026c82"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "set %params%=hello" fullword
		$s2 = "me\\canWell.js hello" fullword
		$s3 = "cexe lldnur" fullword
		$s4 = "revreSretsigeRllD" fullword

	condition:
		$s1 at 0 and filesize <500 and all of them
}
