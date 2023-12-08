import "pe"

rule MAL_BurningUmbrella_Sample_2
{
	meta:
		description = "Detects malware sample from Burning Umbrella report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://401trg.pw/burning-umbrella/"
		date = "2018-05-04"
		hash1 = "801a64a730fc8d80e17e59e93533c1455686ca778e6ba99cf6f1971a935eda4c"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 40 00 00 E0 63 68 72 6F 6D 67 75 78 }
		$s2 = { 40 00 00 E0 77 62 68 75 74 66 6F 61 }
		$s3 = "ActiveX Manager" wide

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and $s1 in (0..1024) and $s2 in (0..1024) and $s3
}
