rule md5_28690a72362e021f65bb74eecc54255e
{
	meta:
		description = "Detects a specific curl_setopt command with CURLOPT_POSTFIELDS and http_build_query"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "curl_setopt($ch, CURLOPT_POSTFIELDS,http_build_query(array('data'=>$data,'utmp'=>$id)));"

	condition:
		any of them
}
