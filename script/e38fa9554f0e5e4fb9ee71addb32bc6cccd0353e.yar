rule CN_Honker_Webshell_Serv_U_asp
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file Serv-U asp.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cee91cd462a459d31a95ac08fe80c70d2f9c1611"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii
		$s2 = "<td><input name=\"c\" type=\"text\" id=\"c\" value=\"cmd /c net user goldsun lov" ascii
		$s3 = "deldomain = \"-DELETEDOMAIN\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \" PortNo=\"" ascii

	condition:
		filesize <30KB and 2 of them
}
