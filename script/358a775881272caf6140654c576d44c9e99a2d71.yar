rule FVEY_ShadowBroker_nopen_oneshot
{
	meta:
		description = "Auto-generated rule - file oneshot.example"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		date = "2016-12-17"
		hash1 = "a85b260d6a53ceec63ad5f09e1308b158da31062047dc0e4d562d2683a82bf9a"
		os = "linux"
		filetype = "script"

	strings:
		$s1 = "/sbin/sh -c (mkdir /tmp/.X11R6; cd /tmp/.X11R6 && telnet" ascii

	condition:
		1 of them
}
