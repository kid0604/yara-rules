rule CN_Honker_Webshell_Serv_U_2_admin_by_lake2
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U 2 admin by lake2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cb8039f213e611ab2687edd23e63956c55f30578"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii
		$s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii
		$s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii
		$s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii

	condition:
		filesize <17KB and 2 of them
}
