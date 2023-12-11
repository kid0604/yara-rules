rule FVEY_ShadowBroker_user_tool_earlyshovel
{
	meta:
		description = "Auto-generated rule - file user.tool.earlyshovel.COMMON"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		date = "2016-12-17"
		hash1 = "504e7a376c21ffbfb375353c5451dc69a35a10d7e2a5d0358f9ce2df34edf256"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$x1 = "--tip 127.0.0.1 --tport 2525 --cip REDIRECTOR_IP --cport RANDOM_PORT" ascii

	condition:
		1 of them
}
