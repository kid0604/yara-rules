rule CN_Honker_mssqlpw_scan
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file mssqlpw scan.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e49def9d72bfef09a639ef3f7329083a0b8b151c"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "response.Write(\"I Get it ! Password is <font color=red>\" & str & \"</font><BR>" ascii
		$s1 = "response.Write \"Done!<br>Process \" & tTime & \" s\"" fullword ascii

	condition:
		filesize <6KB and all of them
}
