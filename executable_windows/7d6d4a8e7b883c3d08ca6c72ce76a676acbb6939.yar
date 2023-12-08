rule FVEY_ShadowBroker_strifeworld
{
	meta:
		description = "Auto-generated rule - file strifeworld.1"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		date = "2016-12-17"
		hash1 = "222b00235bf143645ad0d55b2b6839febc5b570e3def00b77699915a7c9cb670"
		os = "windows"
		filetype = "executable"

	strings:
		$s4 = "-p -n.\" strifeworld" fullword ascii
		$s5 = "Running STRIFEWORLD not protected" ascii

	condition:
		1 of them
}
