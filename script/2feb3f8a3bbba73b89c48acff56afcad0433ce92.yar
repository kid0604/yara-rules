rule Empire_Invoke_DllInjection
{
	meta:
		description = "Detects Empire component - file Invoke-DllInjection.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "304031aa9eca5a83bdf1f654285d86df79cb3bba4aa8fe1eb680bd5b2878ebf0"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "-Dll evil.dll" fullword ascii

	condition:
		( uint16(0)==0x7566 and filesize <40KB and 1 of them ) or all of them
}
