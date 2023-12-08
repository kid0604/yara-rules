import "pe"

rule SecurityXploded_Producer_String
{
	meta:
		description = "Detects hacktools by SecurityXploded"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://securityxploded.com/browser-password-dump.php"
		date = "2017-07-13"
		score = 60
		hash1 = "d57847db5458acabc87daee6f30173348ac5956eb25e6b845636e25f5a56ac59"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "http://securityxploded.com" fullword ascii

	condition:
		( uint16(0)==0x5a4d and all of them )
}
