rule FSO_s_ajan
{
	meta:
		description = "Webshells Auto-generated - file ajan.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "22194f8c44524f80254e1b5aec67b03e"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s4 = "entrika.write \"BinaryStream.SaveToFile"

	condition:
		all of them
}
