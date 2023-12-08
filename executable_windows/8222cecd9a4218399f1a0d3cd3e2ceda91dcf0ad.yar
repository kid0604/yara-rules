import "pe"

rule Disclosed_0day_POCs_shellcodegenerator
{
	meta:
		description = "Detects POC code from disclosed 0day hacktool set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed 0day Repos"
		date = "2017-07-07"
		hash1 = "55c4073bf8d38df7d392aebf9aed2304109d92229971ffac6e1c448986a87916"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\Release\\shellcodegenerator.pdb" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <40KB and all of them )
}
