import "hash"
import "pe"

rule Mirai_Dwnl : MALW
{
	meta:
		description = "Mirai Downloader"
		author = "Joan Soriano / @joanbtl"
		date = "2017-04-16"
		version = "1.0"
		MD5 = "85784b54dee0b7c16c57e3a3a01db7e6"
		SHA1 = "6f6c625ef730beefbc23c7f362af329426607dee"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "GET /mirai/"
		$s2 = "dvrHelper"

	condition:
		$s1 and $s2
}
