rule bin_Client
{
	meta:
		description = "Webshells Auto-generated - file Client.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "5f91a5b46d155cacf0cc6673a2a5461b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Recieved respond from server!!"
		$s4 = "packet door client"
		$s5 = "input source port(whatever you want):"
		$s7 = "Packet sent,waiting for reply..."

	condition:
		all of them
}
