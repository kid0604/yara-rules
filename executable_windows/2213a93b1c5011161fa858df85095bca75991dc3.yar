rule BIN_Client
{
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "9f0a74ec81bc2f26f16c5c172b80eca7"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "=====Remote Shell Closed====="
		$s2 = "All Files(*.*)|*.*||"
		$s6 = "WSAStartup Error!"
		$s7 = "SHGetFileInfoA"
		$s8 = "CreateThread False!"
		$s9 = "Port Number Error"

	condition:
		4 of them
}
