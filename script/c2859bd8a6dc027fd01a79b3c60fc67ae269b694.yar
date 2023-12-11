rule webshell_404_data_suiyue
{
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"

	condition:
		all of them
}
