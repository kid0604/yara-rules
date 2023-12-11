rule FVEY_ShadowBroker_eleganteagle_opscript_1_0_0
{
	meta:
		description = "Auto-generated rule - file eleganteagle_opscript.1.0.0.6"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://bit.no.com:43110/theshadowbrokers.bit/post/message6/"
		date = "2016-12-17"
		hash1 = "57e223318de0a802874642652b3dc766128f25d7e8f320c6f04c6f2659bb4f7f"
		os = "windows"
		filetype = "script"

	strings:
		$x3 = "uploadnrun -e \"D=-ucIP_ADDRESS_OF_REDIR" ascii

	condition:
		1 of them
}
