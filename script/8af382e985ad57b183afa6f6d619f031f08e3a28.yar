rule CN_Honker_Webshell_Interception3389_get
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file get.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ceb6306f6379c2c1634b5058e1894b43abcf0296"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii
		$s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii
		$s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii

	condition:
		filesize <3KB and all of them
}
