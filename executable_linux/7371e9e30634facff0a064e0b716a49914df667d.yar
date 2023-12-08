import "hash"
import "pe"

rule Mirai_3_alt_1 : MALW
{
	meta:
		description = "Mirai Variant 3"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "bb22b1c921ad8fa358d985ff1e51a5b8"
		SHA1 = "432ef83c7692e304c621924bc961d95c4aea0c00"
		os = "linux"
		filetype = "executable"

	strings:
		$dir1 = "/dev/watchdog"
		$dir2 = "/dev/misc/watchdog"
		$s1 = "PMMV"
		$s2 = "ZOJFKRA"
		$s3 = "FGDCWNV"
		$s4 = "OMVJGP"
		$ssl = "ssl3_ctrl"

	condition:
		$dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and not $ssl
}
