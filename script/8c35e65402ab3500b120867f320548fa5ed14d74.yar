rule APT_MAL_CN_Wocao_info_vbs
{
	meta:
		description = "Strings from the information grabber VBS"
		author = "Fox-IT SRT"
		reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
		os = "windows"
		filetype = "script"

	strings:
		$ = "Logger PingConnect"
		$ = "Logger GetAdmins"
		$ = "Logger InstallPro"
		$ = "Logger Exec"
		$ = "retstr = adminsName & \" Members\" & vbCrLf & _"
		$ = "Logger VolumeName & \" (\" & objDrive.DriveLetter & \":)\" _"
		$ = "txtRes = txtRes & machine & \" can"
		$ = "retstr = \"PID   SID Image Name\" & vbCrLf & \"===="

	condition:
		4 of them
}
