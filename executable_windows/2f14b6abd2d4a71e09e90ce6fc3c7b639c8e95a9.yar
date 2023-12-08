rule HYTop2006_rar_Folder_2006X2
{
	meta:
		description = "Webshells Auto-generated - file 2006X2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cc5bf9fc56d404ebbc492855393d7620"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Powered By "
		$s3 = " \" onClick=\"this.form.sharp.name=this.form.password.value;this.form.action=this."

	condition:
		all of them
}
