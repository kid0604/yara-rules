import "pe"

rule wannacry_memory_ransom : wannacry_memory_ransom
{
	meta:
		description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"
		author = "Blueliv"
		reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"
		date = "2017-05-15"
		os = "windows"
		filetype = "executable"

	strings:
		$s01 = "%08X.eky"
		$s02 = "%08X.pky"
		$s03 = "%08X.res"
		$s04 = "%08X.dky"
		$s05 = "@WanaDecryptor@.exe"

	condition:
		all of them
}
