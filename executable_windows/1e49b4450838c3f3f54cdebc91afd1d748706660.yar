import "pe"

rule INDICATOR_EXE_Packed_NyanXCat_CSharpLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects .NET executables utilizing NyanX-CAT C# Loader"
		snort2_sid = "930073-930075"
		snort3_sid = "930026"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 00 50 72 6f 67 72 61 6d 00 4c 6f 61 64 65 72 00 4e 79 61 6e 00 }

	condition:
		uint16(0)==0x5a4d and all of them
}
