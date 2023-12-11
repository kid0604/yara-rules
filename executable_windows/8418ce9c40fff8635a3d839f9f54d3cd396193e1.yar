rule by063cli
{
	meta:
		description = "Webshells Auto-generated - file by063cli.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "49ce26eb97fd13b6d92a5e5d169db859"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "#popmsghello,are you all right?"
		$s4 = "connect failed,check your network and remote ip."

	condition:
		all of them
}
