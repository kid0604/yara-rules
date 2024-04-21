rule gozi_17386_adcomp_bat
{
	meta:
		description = "Gozi - file adcomp.bat"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/01/09/unwrapping-ursnifs-gifts"
		date = "2023-01-08"
		hash1 = "eb2335e887875619b24b9c48396d4d48"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "powershell" fullword
		$s2 = ">> log2.txt" fullword
		$s3 = "Get-ADComputer" fullword

	condition:
		$s1 at 0 and filesize <500 and all of them
}
