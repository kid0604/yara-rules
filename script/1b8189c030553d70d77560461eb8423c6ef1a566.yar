rule FVEY_ShadowBroker_user_tool_epichero
{
	meta:
		description = "Auto-generated rule - file user.tool.epichero.COMMON"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		date = "2016-12-17"
		hash1 = "679d194c32cbaead7281df9afd17bca536ee9d28df917b422083ae8ed5b5c484"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x2 = "-irtun TARGET_IP ISH_CALLBACK_PORT"
		$x3 = "-O REVERSE_SHELL_CALLBACK_PORT -w HIDDEN_DIR" fullword ascii

	condition:
		1 of them
}
