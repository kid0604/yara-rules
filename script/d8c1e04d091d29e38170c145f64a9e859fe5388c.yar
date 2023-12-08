rule Hacktools_CN_Burst_Blast
{
	meta:
		description = "Disclosed hacktool set - file Blast.bat"
		author = "Florian Roth"
		date = "17.11.14"
		score = 60
		hash = "b07702a381fa2eaee40b96ae2443918209674051"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "@sql.exe -f ip.txt -m syn -t 3306 -c 5000 -u http:" ascii
		$s1 = "@echo off" fullword ascii

	condition:
		all of them
}
