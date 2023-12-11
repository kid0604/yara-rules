rule MW_neuron2_dotnet_strings : Turla APT
{
	meta:
		description = "Rule for detection of the .NET payload for Neuron2 based on strings used"
		author = "NCSC"
		family = "Turla"
		reference = "https://www.ncsc.gov.uk/alerts/turla-group-malware"
		date = "2018-01-18"
		hash1 = "83d8922e7a8212f1a2a9015973e668d7999b90e7000c31f57be83803747df015"
		os = "windows"
		filetype = "executable"

	strings:
		$dotnetMagic = "BSJB" ascii
		$s1 = "http://*:80/W3SVC/" wide
		$s2 = "https://*:443/W3SVC/" wide
		$s3 = "neuron2.exe" ascii
		$s4 = "D:\\Develop\\sps\\neuron2\\neuron2\\obj\\Release\\neuron2.pdb" ascii

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and $dotnetMagic and 2 of ($s*)
}
