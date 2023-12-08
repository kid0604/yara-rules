import "pe"

rule Wanna_Sample_4da1f312a214c07143abeeafb695d904 : Wanna_Sample_4da1f312a214c07143abeeafb695d904
{
	meta:
		description = "Specific sample match for WannaCryptor"
		MD5 = "4da1f312a214c07143abeeafb695d904"
		SHA1 = "b629f072c9241fd2451f1cbca2290197e72a8f5e"
		SHA256 = "aee20f9188a5c3954623583c6b0e6623ec90d5cd3fdec4e1001646e27664002c"
		INFO = "Looks for offsets of r.wry and s.wry instances"
		os = "windows"
		filetype = "executable"

	strings:
		$rwnry = { 72 2e 77 72 79 }
		$swnry = { 73 2e 77 72 79 }

	condition:
		$rwnry at 88195 and $swnry at 88656 and $rwnry at 4495639
}
