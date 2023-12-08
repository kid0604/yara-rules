import "pe"

rule MALWARE_Win_RomCom_Dropper
{
	meta:
		author = "ditekShen"
		description = "Hunt for RomCom worker"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide nocase
		$s2 = "\\REGISTRY\\USER" wide nocase
		$s3 = "BINARY" fullword wide
		$s4 = "POST" fullword wide

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and pe.number_of_exports==1 and pe.exports("Main") and 3 of them
}
