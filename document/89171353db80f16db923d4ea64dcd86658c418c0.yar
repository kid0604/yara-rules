rule Docm_in_PDF
{
	meta:
		description = "Detects an embedded DOCM in PDF combined with OpenAction"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-05-15"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
		$a2 = "OpenAction" ascii fullword
		$a3 = "JavaScript" ascii fullword

	condition:
		uint32(0)==0x46445025 and all of them
}
