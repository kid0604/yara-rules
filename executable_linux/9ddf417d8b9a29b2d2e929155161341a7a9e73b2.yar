import "pe"
import "hash"

rule Mirai_5_alt_1 : MALW
{
	meta:
		description = "Mirai Variant 5"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "7e17c34cddcaeb6755c457b99a8dfe32"
		SHA1 = "b63271672d6a044704836d542d92b98e2316ad24"
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
		$dir1 and $dir2 and $s1 and $s2 and $s3 and $s4 and $ssl
}
