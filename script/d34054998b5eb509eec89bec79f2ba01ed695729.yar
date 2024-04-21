rule M_Hunting_Dropper_WIREFIRE_1
{
	meta:
		author = "Mandiant"
		description = "This rule detects WIREFIRE, a web shell written in Python that exists as trojanized logic to a component of the pulse secure appliance."
		md5 = "6de651357a15efd01db4e658249d4981"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		date = "2024-01-11"
		score = 75
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "zlib.decompress(aes.decrypt(base64.b64decode(" ascii
		$s2 = "aes.encrypt(t+('\\x00'*(16-len(t)%16))" ascii
		$s3 = "Handles DELETE request to delete an existing visits data." ascii
		$s4 = "request.data.decode().startswith('GIF'):" ascii
		$s5 = "Utils.api_log_admin" ascii

	condition:
		filesize <10KB and all of them
}
