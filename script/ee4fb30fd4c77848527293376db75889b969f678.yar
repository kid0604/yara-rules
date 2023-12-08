rule CN_Honker_Webshell_T00ls_Lpk_Sethc_v4_mail
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file mail.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0a9b7b438591ee78ee573028cbb805a9dbb9da96"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "if (!$this->smtp_putcmd(\"AUTH LOGIN\", base64_encode($this->user)))" fullword ascii
		$s2 = "$this->smtp_debug(\"> \".$cmd.\"\\n\");" fullword ascii

	condition:
		filesize <39KB and all of them
}
