rule Empire_dumpCredStore
{
	meta:
		description = "Detects Empire component - file dumpCredStore.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "c1e91a5f9cc23f3626326dab2dcdf4904e6f8a332e2bce8b9a0854b371c2b350"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "[DllImport(\"Advapi32.dll\", SetLastError = true, EntryPoint = \"CredReadW\"" ascii
		$s12 = "[String] $Msg = \"Failed to enumerate credentials store for user '$Env:UserName'\"" fullword ascii
		$s15 = "Rtn = CredRead(\"Target\", CRED_TYPE.GENERIC, out Cred);" fullword ascii

	condition:
		( uint16(0)==0x233c and filesize <40KB and 1 of them ) or all of them
}
