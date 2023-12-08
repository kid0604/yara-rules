rule Empire_Get_SecurityPackages
{
	meta:
		description = "Detects Empire component - file Get-SecurityPackages.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "5d06e99121cff9b0fce74b71a137501452eebbcd1e901b26bde858313ee5a9c1"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$null = $EnumBuilder.DefineLiteral('LOGON', 0x2000)" fullword ascii
		$s2 = "$EnumBuilder = $ModuleBuilder.DefineEnum('SSPI.SECPKG_FLAG', 'Public', [Int32])" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <20KB and 1 of them ) or all of them
}
