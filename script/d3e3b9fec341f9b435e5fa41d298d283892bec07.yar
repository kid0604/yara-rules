rule WaterPamola_phpstealer_encode
{
	meta:
		description = "PHP stealer using water pamola"
		author = "JPCERT/CC Incident Response Group"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$func1 = "header(\"Access-Control-Allow-Origin: *\");"
		$func2 = "$ip=@$_SERVER['HTTP_CF_CONNECTING_IP'];"
		$func3 = "@$errlogs=fopen(pack('H*'"
		$func4 = "@$write=fwrite($errlogs,$mode);"

	condition:
		uint32(0)==0x68703F3C and all of them
}
