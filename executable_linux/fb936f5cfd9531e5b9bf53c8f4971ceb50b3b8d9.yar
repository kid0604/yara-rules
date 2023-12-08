import "pe"
import "hash"

rule Mirai_4_alt_1 : MALW
{
	meta:
		description = "Mirai Variant 4"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "f832ef7a4fcd252463adddfa14db43fb"
		SHA1 = "4455d237aadaf28aafce57097144beac92e55110"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "210765"
		$s2 = "qllw"
		$s3 = ";;;;;;"

	condition:
		$s1 and $s2 and $s3
}
