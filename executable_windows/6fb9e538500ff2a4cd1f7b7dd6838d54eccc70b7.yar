rule sendmail
{
	meta:
		description = "Webshells Auto-generated - file sendmail.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "75b86f4a21d8adefaf34b3a94629bd17"
		os = "windows"
		filetype = "executable"

	strings:
		$s3 = "_NextPyC808"
		$s6 = "Copyright (C) 2000, Diamond Computer Systems Pty. Ltd. (www.diamondcs.com.au)"

	condition:
		all of them
}
