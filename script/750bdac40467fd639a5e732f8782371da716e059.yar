rule CN_Honker_Webshell_Tuoku_script_mssql_2
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mssql.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ad55512afa109b205e4b1b7968a89df0cf781dc9"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "sqlpass=request(\"sqlpass\")" fullword ascii
		$s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii
		$s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii

	condition:
		filesize <3KB and all of them
}
