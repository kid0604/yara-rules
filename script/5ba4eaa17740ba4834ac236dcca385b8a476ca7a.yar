rule hidden_file_upload_in_503
{
	meta:
		description = "Detects hidden file uploads in 503 error pages"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /error_reporting\(0\);\$f=\$_FILES\[\w+\];copy\(\$f\[tmp_name\],\$f\[name\]\);error_reporting\(E_ALL\);/

	condition:
		any of them
}
