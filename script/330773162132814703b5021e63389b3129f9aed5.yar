rule CN_Honker_Webshell_Serv_U_serv_u
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file serv-u.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2023-01-27"
		score = 70
		hash = "1c6415a247c08a63e3359b06575b36017befc0c0"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "@readfile(\"c:\\\\winnt\\\\system32\\" ascii
		$s2 = "$sendbuf = \"PASS \".$_POST[\"password\"].\"\\r\\n\";" fullword ascii
		$s3 = "$cmd=\"cmd /c rundll32.exe $path,install $openPort $activeStr\";" fullword ascii

	condition:
		filesize <435KB and all of them
}
