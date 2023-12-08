import "pe"

rule kelihos_botnet_pdb
{
	meta:
		description = "Detect the risk of Botnet Malware Kelihos Rule 2"
		hash = "f0a6d09b5f6dbe93a4cf02e120a846073da2afb09604b7c9c12b2e162dfe7090"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb = "\\Only\\Must\\Not\\And.pdb"
		$pdb1 = "\\To\\Access\\Do.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <1440KB and any of them
}
