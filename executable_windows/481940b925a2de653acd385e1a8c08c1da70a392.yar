import "pe"

rule INDICATOR_EXE_Packed_SimplePolyEngine
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Sality Polymorphic Code Generator or Simple Poly Engine or Sality"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Simple Poly Engine v" ascii
		$b1 = "yrf<[LordPE]" ascii
		$b2 = "Hello world!" fullword wide

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or all of ($b*))
}
