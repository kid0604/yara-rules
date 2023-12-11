rule CN_Honker_Webshell_Serv_U_by_Goldsun
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U_by_Goldsun.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d4d7a632af65a961a1dbd0cff80d5a5c2b397e8c"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii
		$s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
		$s3 = "127.0.0.1:<%=port%>," fullword ascii
		$s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii

	condition:
		filesize <30KB and 2 of them
}
