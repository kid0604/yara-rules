rule LOG_Exchange_Forensic_Artefacts_CleanUp_Activity_Mar21_1 : LOG
{
	meta:
		description = "Detects forensic artefacts showing cleanup activity found in HAFNIUM intrusions exploiting"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/jdferrell3/status/1368626281970024448"
		date = "2021-03-08"
		score = 70
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "cmd.exe /c cd /d C:/inetpub/wwwroot/aspnet_client" ascii wide
		$x2 = "cmd.exe /c cd /d C:\\inetpub\\wwwroot\\aspnet_client" ascii wide
		$s1 = "aspnet_client&del '"
		$s2 = "aspnet_client&attrib +h +s +r "
		$s3 = "&echo [S]"

	condition:
		1 of ($x*) or 2 of them
}
