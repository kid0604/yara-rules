rule reDuhServers_reDuh_2
{
	meta:
		description = "Chinese Hacktool Set - file reDuh.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "512d0a3e7bb7056338ad0167f485a8a6fa1532a3"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "errorlog(\"FRONTEND: send_command '\".$data.\"' on port \".$port.\" returned \"." ascii
		$s2 = "$msg = \"newData:\".$socketNumber.\":\".$targetHost.\":\".$targetPort.\":\".$seq" ascii
		$s3 = "errorlog(\"BACKEND: *** Socket key is \".$sockkey);" fullword ascii

	condition:
		filesize <57KB and all of them
}
