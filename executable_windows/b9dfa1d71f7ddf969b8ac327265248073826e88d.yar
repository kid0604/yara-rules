import "pe"

rule PubSabCode : PubSab Family
{
	meta:
		description = "PubSab code tricks"
		author = "Seth Hardy"
		last_modified = "2014-06-19"
		os = "windows"
		filetype = "executable"

	strings:
		$decrypt = { 6B 45 E4 37 89 CA 29 C2 89 55 E4 }

	condition:
		any of them
}
