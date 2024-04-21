import "pe"

rule mal_host2_locker
{
	meta:
		description = "mal - file locker.bat"
		author = "TheDFIRReport"
		date = "2021-11-29"
		hash1 = "1edfae602f195d53b63707fe117e9c47e1925722533be43909a5d594e1ef63d3"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "_locker.exe -m -net -size 10 -nomutex -p" ascii

	condition:
		uint16(0)==0x7473 and filesize <8KB and $x1
}
