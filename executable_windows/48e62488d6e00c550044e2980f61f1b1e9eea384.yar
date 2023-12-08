import "pe"

rule EXT_APT32_goopdate_installer
{
	meta:
		reference = "https://about.fb.com/news/2020/12/taking-action-against-hackers-in-bangladesh-and-vietnam/"
		author = "Facebook"
		description = "Detects APT32 installer side-loaded with goopdate.dll"
		sample = "69730f2c2bb9668a17f8dfa1f1523e0e1e997ba98f027ce98f5cbaa869347383"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = { 68 ?? ?? ?? ?? 57 A3 ?? ?? ?? ?? FF D6 33 05 ?? ?? ?? ?? }
		$s1 = "GetProcAddress"
		$s2 = { 8B 4D FC ?? ?? 0F B6 51 0C ?? ?? 8B 4D F0 0F B6 1C 01 33 DA }
		$s3 = "FindNextFileW"
		$s4 = "Process32NextW"

	condition:
		(pe.is_64bit() or pe.is_32bit()) and all of them
}
