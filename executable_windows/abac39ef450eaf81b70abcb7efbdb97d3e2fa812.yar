rule pdb_strings_Rescator
{
	meta:
		author = "@patrickrolsen"
		maltype = "Target Attack"
		version = "0.3"
		description = "Rescator PDB strings within binaries"
		date = "01/30/2014"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "\\Projects\\Rescator" nocase

	condition:
		uint16(0)==0x5A4D and $pdb1
}
