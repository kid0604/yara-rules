import "pe"

rule Armadillo3X5XSiliconRealmsToolworks
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo3X5XSiliconRealmsToolworks malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 60 33 C9 75 02 EB 15 EB 33 }

	condition:
		$a0 at pe.entry_point
}
