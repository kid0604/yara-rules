rule by064cli
{
	meta:
		description = "Webshells Auto-generated - file by064cli.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "10e0dff366968b770ae929505d2a9885"
		os = "windows"
		filetype = "executable"

	strings:
		$s7 = "packet dropped,redirecting"
		$s9 = "input the password(the default one is 'by')"

	condition:
		all of them
}
