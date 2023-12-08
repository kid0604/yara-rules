import "pe"

rule Loader_MSIL_DUEDLLIGENCE_2
{
	meta:
		author = "FireEye"
		description = "Detects the presence of the DueDLLigence loader"
		os = "windows"
		filetype = "executable"

	strings:
		$1 = "DueDLLigence" fullword
		$2 = "CPlApplet" fullword
		$iz1 = /_Cor(Exe|Dll)Main/ fullword

	condition:
		( uint16(0)==0x5A4D) and ( uint32( uint32(0x3C))==0x00004550) and all of them
}
