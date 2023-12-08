rule dbgiis6cli
{
	meta:
		description = "Webshells Auto-generated - file dbgiis6cli.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3044dceb632b636563f66fee3aaaf8f3"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)"
		$s5 = "###command:(NO more than 100 bytes!)"

	condition:
		all of them
}
