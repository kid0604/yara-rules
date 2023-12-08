import "pe"
import "hash"

rule Mirai_1_alt_1 : MALW
{
	meta:
		description = "Mirai Variant 1"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "655c3cf460489a7d032c37cd5b84a3a8"
		SHA1 = "4dd3803956bc31c8c7c504734bddec47a1b57d58"
		os = "linux"
		filetype = "executable"

	strings:
		$dir1 = "/dev/watchdog"
		$dir2 = "/dev/misc/watchdog"
		$pass1 = "PMMV"
		$pass2 = "FGDCWNV"
		$pass3 = "OMVJGP"

	condition:
		$dir1 and $pass1 and $pass2 and not $pass3 and not $dir2
}
