rule html_upload
{
	meta:
		description = "Detects HTML file upload functionality"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "<input type='submit' name='upload' value='upload'>"
		$ = "if($_POST['upload'])"

	condition:
		any of them and filesize <500KB
}
